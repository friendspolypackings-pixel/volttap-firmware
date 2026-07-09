/* =====================================================================
   VOLTTAP 2CH SMART SWITCH — FIRMWARE (Local OTA + CLOUD OTA, heap-safe)
   ---------------------------------------------------------------------
   Board  : Generic ESP8266 Module (ESP-12F)

   CLOUD OTA எப்படி வேலை செய்யுது (heap-safe design):
     1) loop()-ல Firebase-ல /fw_version படிக்கும்
     2) server version பெரிசுனா -> /fw_url-ஐ EEPROM-ல எழுதி,
        ஒரு flag போட்டு, ESP.restart()
     3) Boot ஆகும்போது, WiFi connect ஆனதும், FIREBASE START பண்ணற
        முன்னாடியே flag-ஐ பாத்து .bin download பண்ணும்
        -> அப்போ heap ~40KB free, secure download வேலை செய்யும்
     4) Download முடிஞ்சதும் தானா reboot -> புது firmware ஓடும்

   ஏன் இப்படி: Firebase ஓடிக்கிட்டு இருந்தா heap 18KB தான் மிச்சம்.
   GitHub https download-ku ~25-30KB வேணும். So Firebase-ku முன்னாடி
   download பண்ணணும்.

   Flag-ஐ download-க்கு முன்னாடியே அழிக்கிறோம் -> fail ஆனாலும்
   infinite loop-ல மாட்டாது.

   !!!!!!!!!!!!!!!!!!!! RELEASE வரிசை (மறக்காத) !!!!!!!!!!!!!!!!!!!!
     1) FW_VERSION_NUM ஏத்து
     2) Export Compiled Binary -> புது .bin
     3) .bin-ஐ GitHub-ல ஏத்து
     4) Firebase-ல fw_url மாத்து (புது file பேர்)
     5) கடைசியா Firebase-ல fw_version ஏத்து
   !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

   Pins:  CH1 relay=GPIO5, CH2 relay=GPIO4
          CH1 btn=GPIO12, CH2 btn=GPIO13 (internal pull-up)
          WiFi btn=GPIO16 (external 10k pull-up)
   Serial @ 74880 baud.
   ===================================================================== */

#include <ESP8266WiFi.h>
#include <WiFiManager.h>
#include <ArduinoOTA.h>
#include <EEPROM.h>
#include <Firebase_ESP_Client.h>
#include "addons/TokenHelper.h"
#include "addons/RTDBHelper.h"

/* ---------- CLOUD OTA ---------- */
#include <ESP8266HTTPClient.h>
#include <ESP8266httpUpdate.h>
#include <WiFiClientSecure.h>

/* ---------- Firmware version ---------- */
#define FW_VERSION_NUM  14          // <<< புது release-ல இத ஏத்து!
#define FW_VERSION      "v14.0"     // display மட்டும்

/* ---------- Firebase ---------- */
#define API_KEY         "AIzaSyB_gt6qIQ0N8yYbFSqp859T04W1z0zNNUo"
#define DATABASE_URL    "https://smart-switch-49ddc-default-rtdb.asia-southeast1.firebasedatabase.app/"

/* ---------- Setup hotspot ---------- */
#define AP_NAME         "MONGAY-SETUP"
#define AP_PASSWORD     "12345678"

/* ---------- Local OTA ---------- */
#define OTA_HOSTNAME    "Volttap-2CH"
#define OTA_PASSWORD    "volttap123"

/* ---------- Cloud OTA timing ---------- */
#define CLOUD_OTA_FIRST_DELAY_MS   10000UL       // boot ஆன 10 sec-ல முதல் check
#define CLOUD_OTA_INTERVAL_MS      21600000UL    // அப்புறம் 6 மணி நேரம்

/* ---------- Relay pins ---------- */
#define CH1   5
#define CH2   4

/* ---------- Button pins ---------- */
#define BTN_CH1   12
#define BTN_CH2   13
#define BTN_WIFI  16

/* ---------- DEBUG ---------- */
#define DEBUG_BTN  0

/* ---------- EEPROM ----------
   0  : relay magic
   1  : relay1
   2  : relay2
   3  : OTA flag  (0xA5 = boot-ல OTA பண்ணு)
   16.. : OTA URL (null terminated, max 200)                */
#define EEPROM_SIZE     256
#define EE_MAGIC_ADDR     0
#define EE_R1_ADDR        1
#define EE_R2_ADDR        2
#define EE_OTA_FLAG_ADDR  3
#define EE_URL_ADDR      16
#define EE_URL_MAXLEN   200
#define EE_MAGIC       0x5A
#define EE_OTA_MAGIC   0xA5

/* ---------- BRICK PROTECTION (v9) ----------
   addr 4 : boot-fail counter (connect ஆகாத boot எண்ணிக்கை)
   addr 5 : safe-mode flag  (0x53 = safe mode-ல இருக்கு)          */
#define EE_BOOTFAIL_ADDR  4
#define EE_SAFEMODE_ADDR  5
#define EE_SAFE_MAGIC   0x53
#define BOOTFAIL_LIMIT     3      // 3 தடவ connect ஆகல -> safe mode

/* ---------- DOWNLOAD-FAIL RETRY (v11) ----------
   addr 6 : download-fail counter (இந்த version எத்தன தடவ download fail)
   addr 7 : bad version number (எந்த version fail ஆச்சு)                */
#define EE_DLFAIL_ADDR    6
#define EE_BADVER_ADDR    7
#define EE_TARGETVER_ADDR 9      // OTA target version (boot OTA fail record-ku)
#define EE_DIAGINIT_ADDR 10      // diagnostics init magic (garbage clean)
#define EE_DIAG_MAGIC   0xD1
#define DLFAIL_LIMIT       3      // 3 தடவ download fail -> அந்த version-ah skip

/* ---------- Firebase objects ---------- */
FirebaseData   fbdo;
FirebaseAuth   auth;
FirebaseConfig config;

bool signupOK = false;
unsigned long lastRead = 0;
bool relayState[2] = {false, false};
bool bootSyncDone = false;

/* ---------- button lock ---------- */
unsigned long lastBtnChange[2] = {0, 0};
const unsigned long BTN_LOCK_MS = 2500;

/* ---------- WiFi reset button ---------- */
unsigned long wifiBtnPressStart = 0;
const unsigned long WIFI_RESET_HOLD_MS = 3000;

/* ---------- SSL-fail restart counter ---------- */
int fbFailCount = 0;
const int FB_FAIL_LIMIT = 5;

unsigned long lastDbg = 0;

/* ---------- Cloud OTA state ---------- */
unsigned long lastCloudOtaCheck = 0;

/* ---------- DIAGNOSTICS (v13) ---------- */
unsigned long lastStatusPush = 0;
#define STATUS_PUSH_INTERVAL_MS   60000UL   // 1 நிமிஷத்துக்கு ஒரு தரம் status எழுது
#define HEALTH_COMMIT_DELAY_MS    30000UL   // 30 sec stable ஓடின பிறகு தான் "healthy"
bool firstCloudOtaDone = false;

/* ==================================================================
   EEPROM helpers
   ================================================================== */
void saveRelayState() {
  EEPROM.write(EE_R1_ADDR, relayState[0] ? 1 : 0);
  EEPROM.write(EE_R2_ADDR, relayState[1] ? 1 : 0);
  EEPROM.write(EE_MAGIC_ADDR, EE_MAGIC);
  EEPROM.commit();
}

void loadRelayState() {
  if (EEPROM.read(EE_MAGIC_ADDR) == EE_MAGIC) {
    relayState[0] = (EEPROM.read(EE_R1_ADDR) == 1);
    relayState[1] = (EEPROM.read(EE_R2_ADDR) == 1);
    Serial.printf(">> Restored state: CH1=%s CH2=%s\n",
                  relayState[0] ? "ON" : "OFF",
                  relayState[1] ? "ON" : "OFF");
  } else {
    relayState[0] = false;
    relayState[1] = false;
    Serial.println(">> First run: default OFF");
  }
}

/* ---------- OTA request (EEPROM) ---------- */
void saveOtaRequest(const String &url) {
  int len = url.length();
  if (len > EE_URL_MAXLEN - 1) len = EE_URL_MAXLEN - 1;
  for (int i = 0; i < len; i++) EEPROM.write(EE_URL_ADDR + i, url[i]);
  EEPROM.write(EE_URL_ADDR + len, 0);          // null terminator
  EEPROM.write(EE_OTA_FLAG_ADDR, EE_OTA_MAGIC);
  EEPROM.commit();
}

String readOtaUrl() {
  String url = "";
  for (int i = 0; i < EE_URL_MAXLEN; i++) {
    char c = (char)EEPROM.read(EE_URL_ADDR + i);
    if (c == 0) break;
    url += c;
  }
  return url;
}

void clearOtaFlag() {
  EEPROM.write(EE_OTA_FLAG_ADDR, 0x00);
  EEPROM.commit();
}

/* ---------- relay apply (+persist) ---------- */
void setRelay(int idx, int pin, bool val) {
  relayState[idx] = val;
  digitalWrite(pin, val ? HIGH : LOW);
  saveRelayState();
  Serial.printf(">> CH%d : %s\n", idx + 1, val ? "ON" : "OFF");
}

/* ---------- push to Firebase ---------- */
void pushToFirebase(int idx, bool val) {
  if (Firebase.ready() && signupOK) {
    String path = (idx == 0) ? "/relay1" : "/relay2";
    Firebase.RTDB.setBool(&fbdo, path.c_str(), val);
  }
}

/* ==================================================================
   BOOT-TIME CLOUD OTA  (Firebase start பண்ணற முன்னாடி — heap full)
   ================================================================== */
/* ==================================================================
   BRICK PROTECTION helpers (v9)
   ------------------------------------------------------------------
   யோசனை: புது firmware ஏறி, WiFi+Firebase connect ஆனா தான்
   "healthy" -> counter reset. Connect ஆகல-na counter ஏறும்.
   3 தடவ தொடர்ந்து fail -> SAFE MODE (relay/button மட்டும், OTA off).
   Device எந்த நிலையிலும் செத்துப்போகாது.
   ================================================================== */
bool safeMode = false;
bool localOtaReady = false;     // setup early-return ஆனா ArduinoOTA.handle() skip
bool wifiUp = false;
bool healthCommitted = false;

// boot-la counter ஏத்து (இந்த boot fail ஆகலாம் nu முன்கூட்டி வை)
void bootFailIncrement() {
  uint8_t c = EEPROM.read(EE_BOOTFAIL_ADDR);
  if (c == 0xFF) c = 0;              // fresh EEPROM
  c++;
  EEPROM.write(EE_BOOTFAIL_ADDR, c);
  EEPROM.commit();
  Serial.printf(">> Boot-fail counter = %d/%d\n", c, BOOTFAIL_LIMIT);
}

// connect success -> counter 0, "இந்த firmware நல்லது" nu commit
void commitHealthy() {
  if (healthCommitted) return;
  EEPROM.write(EE_BOOTFAIL_ADDR, 0);
  EEPROM.write(EE_SAFEMODE_ADDR, 0x00);
  EEPROM.commit();
  healthCommitted = true;
  Serial.println(">> FIRMWARE HEALTHY — boot-fail counter reset. Commit OK.");
}

// safe-mode-la போகணுமா nu boot-la முடிவு

/* ---------- DOWNLOAD-FAIL RETRY helpers (v11) ---------- */
// இந்த server version ஏற்கனவே "bad" nu mark ஆயிருக்கா?
bool isVersionBad(int ver) {
  int badVer = EEPROM.read(EE_BADVER_ADDR);
  int fails  = EEPROM.read(EE_DLFAIL_ADDR);
  if (badVer == 0xFF) return false;
  return (badVer == ver && fails >= DLFAIL_LIMIT);
}

// download fail ஆச்சு -> counter ஏத்து (அந்த version-ku)
void recordDownloadFail(int ver) {
  int badVer = EEPROM.read(EE_BADVER_ADDR);
  int fails  = EEPROM.read(EE_DLFAIL_ADDR);
  if (badVer != ver || badVer == 0xFF) {   // புது version -> counter fresh
    badVer = ver;
    fails = 0;
  }
  fails++;
  EEPROM.write(EE_BADVER_ADDR, ver);
  EEPROM.write(EE_DLFAIL_ADDR, fails);
  EEPROM.commit();
  Serial.printf(">> Download-fail %d/%d (version %d)\n", fails, DLFAIL_LIMIT, ver);
  if (fails >= DLFAIL_LIMIT) {
    Serial.printf(">> version %d -> BAD nu mark. இனி புது version வரும் வரை skip.\n", ver);
  }
}

// download success (illa புது நல்ல version) -> counter clear
void clearDownloadFail() {
  EEPROM.write(EE_DLFAIL_ADDR, 0);
  EEPROM.write(EE_BADVER_ADDR, 0xFF);
  EEPROM.commit();
}

bool shouldEnterSafeMode() {
  if (EEPROM.read(EE_SAFEMODE_ADDR) == EE_SAFE_MAGIC) return true;
  uint8_t c = EEPROM.read(EE_BOOTFAIL_ADDR);
  if (c != 0xFF && c >= BOOTFAIL_LIMIT) {
    EEPROM.write(EE_SAFEMODE_ADDR, EE_SAFE_MAGIC);   // latch
    EEPROM.commit();
    return true;
  }
  return false;
}

void doBootCloudOTA() {
  if (safeMode) {
    Serial.println(">> SAFE MODE: cloud OTA skip (bad firmware loop தடுக்க).");
    // OTA request flag-ஐயும் அழி — பழைய bad URL மறுபடி download ஆகாம
    EEPROM.write(EE_OTA_FLAG_ADDR, 0x00);
    EEPROM.commit();
    return;
  }
  if (EEPROM.read(EE_OTA_FLAG_ADDR) != EE_OTA_MAGIC) return;

  String url = readOtaUrl();

  // flag-ஐ முன்னாடியே அழி -> fail ஆனா loop-ல மாட்டாது
  clearOtaFlag();

  if (url.length() < 10) {
    Serial.println(">> Boot OTA: URL காலி. Skip.");
    return;
  }

  Serial.println("\n=======================================");
  Serial.println(">> BOOT CLOUD OTA — download ஆரம்பம்");
  Serial.printf(">> URL : %s\n", url.c_str());
  Serial.printf(">> Free heap: %u bytes (இப்போ நிறைய இருக்கு)\n",
                ESP.getFreeHeap());
  Serial.println("=======================================");

  WiFiClientSecure client;
  client.setInsecure();              // cert verify இல்ல (ESP8266-ல heavy)
  // *** HEAP FIX (v12): TLS buffer சின்னதா -> heap சேமி ***
  // Default 16KB+16KB = 32KB (heap 27KB-ல fit ஆகாது).
  // GitHub/Fastly MFLN support -> 512 byte RX போதும். ~27KB save.
  client.setBufferSizes(512, 512);
  Serial.printf(">> TLS buffer 512/512 set. Free heap: %u\n", ESP.getFreeHeap());

  ESPhttpUpdate.rebootOnUpdate(true);
  ESPhttpUpdate.followRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);

  ESPhttpUpdate.onStart([]() { Serial.println(">> Boot OTA: START"); });
  ESPhttpUpdate.onEnd([]()   { Serial.println("\n>> Boot OTA: DONE. Rebooting..."); });
  ESPhttpUpdate.onProgress([](int cur, int total) {
    if (total > 0) Serial.printf(">> Boot OTA: %d%%\r", (cur * 100) / total);
  });
  ESPhttpUpdate.onError([](int err) { Serial.printf("\n>> Boot OTA error[%d]\n", err); });

  t_httpUpdate_return ret = ESPhttpUpdate.update(client, url);

  if (ret == HTTP_UPDATE_FAILED) {
    Serial.printf(">> Boot OTA FAILED (%d): %s\n",
                  ESPhttpUpdate.getLastError(),
                  ESPhttpUpdate.getLastErrorString().c_str());
    int tgt = EEPROM.read(EE_TARGETVER_ADDR);
    recordDownloadFail(tgt);        // v11: fail counter ஏத்து -> loop தடுக்க
    Serial.println(">> பழைய firmware-லயே தொடரும். பரவாயில்ல.");
  } else if (ret == HTTP_UPDATE_NO_UPDATES) {
    Serial.println(">> Boot OTA: no updates");
  }
  // HTTP_UPDATE_OK -> ஏற்கனவே reboot ஆயிடும், இங்க வராது
}

/* ---------- Local OTA setup ---------- */
void setupOTA() {
  ArduinoOTA.setHostname(OTA_HOSTNAME);
  ArduinoOTA.setPassword(OTA_PASSWORD);

  ArduinoOTA.onStart([]() { Serial.println("\n>> Local OTA START..."); });
  ArduinoOTA.onEnd([]()   { Serial.println("\n>> Local OTA DONE. Rebooting..."); });
  ArduinoOTA.onProgress([](unsigned int progress, unsigned int total) {
    Serial.printf(">> Local OTA: %u%%\r", (progress / (total / 100)));
  });
  ArduinoOTA.onError([](ota_error_t error) {
    Serial.printf(">> Local OTA Error[%u]\n", error);
  });

  ArduinoOTA.begin();
  Serial.printf(">> Local OTA ready. IDE Port-ல '%s' தேடு (pass: %s)\n",
                OTA_HOSTNAME, OTA_PASSWORD);
}

/* ==================================================================
   CLOUD OTA CHECK (loop-ல) — version compare மட்டும்.
   update வேணும்னா URL-ஐ EEPROM-ல எழுதி restart.
   ================================================================== */
void checkCloudOTA() {
  if (WiFi.status() != WL_CONNECTED) return;
  if (!Firebase.ready() || !signupOK) return;

  Serial.println("\n>> Cloud OTA: version check...");

  if (!Firebase.RTDB.getInt(&fbdo, "/fw_version")) {
    Serial.printf(">> Cloud OTA: fw_version படிக்க முடியல (%s)\n",
                  fbdo.errorReason().c_str());
    return;
  }
  int serverVersion = fbdo.intData();
  Serial.printf(">> Cloud OTA: device=%d  server=%d\n",
                FW_VERSION_NUM, serverVersion);

  if (serverVersion <= FW_VERSION_NUM) {
    Serial.println(">> Cloud OTA: ஏற்கனவே latest. Update வேண்டாம்.");
    return;
  }

  // *** v11: இந்த version ஏற்கனவே 3 தடவ download fail ஆச்சா? -> skip ***
  if (isVersionBad(serverVersion)) {
    Serial.printf(">> Cloud OTA: version %d ஏற்கனவே %d தடவ fail. Skip (loop தடுக்க).\n",
                  serverVersion, DLFAIL_LIMIT);
    Serial.println(">> புது version (பெரிசு) வந்தா மட்டும் மறுபடி try பண்ணுவேன்.");
    return;
  }

  if (!Firebase.RTDB.getString(&fbdo, "/fw_url")) {
    Serial.printf(">> Cloud OTA: fw_url படிக்க முடியல (%s)\n",
                  fbdo.errorReason().c_str());
    return;
  }
  String url = fbdo.stringData();
  if (url.length() < 10) {
    Serial.println(">> Cloud OTA: fw_url காலி. Skip.");
    return;
  }

  Serial.printf(">> Cloud OTA: புது version %d கிடைச்சது!\n", serverVersion);
  Serial.println(">> URL-ஐ EEPROM-ல சேமிக்கிறேன், restart ஆகி download பண்ணுவேன்");
  Serial.println(">> (Firebase-ku முன்னாடி download -> heap நிறைய இருக்கும்)");

  EEPROM.write(EE_TARGETVER_ADDR, serverVersion);   // fail record-ku target version
  EEPROM.commit();
  saveOtaRequest(url);
  delay(1000);
  ESP.restart();
}

/* ================================================================== */
void setup() {
  Serial.begin(74880);
  delay(500);
  Serial.printf("\n\n=== VOLTTAP 2CH SMART SWITCH (%s, fw=%d) ===\n",
                FW_VERSION, FW_VERSION_NUM);

  EEPROM.begin(EEPROM_SIZE);
  loadRelayState();

  /* ---- v14: முதல் தடவ diagnostics EEPROM clean (garbage போக்க) ---- */
  if (EEPROM.read(EE_DIAGINIT_ADDR) != EE_DIAG_MAGIC) {
    EEPROM.write(EE_DLFAIL_ADDR, 0);
    EEPROM.write(EE_BADVER_ADDR, 0xFF);
    EEPROM.write(EE_TARGETVER_ADDR, 0);
    EEPROM.write(EE_DIAGINIT_ADDR, EE_DIAG_MAGIC);
    EEPROM.commit();
    Serial.println(">> Diagnostics EEPROM initialised (garbage clean).");
  }

  /* ---- v11: இந்த firmware version, download-fail பண்ண version-ஐ தாண்டிடுச்சா?
     தாண்டினா -> அந்த bad-mark clear (நாம வேற வழியில update ஆயிட்டோம்) ---- */
  {
    int badVer = EEPROM.read(EE_BADVER_ADDR);
    if (badVer != 0xFF && FW_VERSION_NUM >= badVer) {
      clearDownloadFail();
      Serial.printf(">> Download-fail clear (fw %d >= bad %d)\n", FW_VERSION_NUM, badVer);
    }
  }

  /* ---- BRICK PROTECTION: boot-la முடிவு ---- */
  safeMode = shouldEnterSafeMode();
  if (safeMode) {
    Serial.println("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    Serial.println(">> SAFE MODE — கெட்ட firmware detect ஆச்சு!");
    Serial.println(">> Relay + button மட்டும் வேலை செய்யும். OTA OFF.");
    Serial.println(">> சரியான firmware push பண்ணி rescue பண்ணு.");
    Serial.println(">> (rescue: Firebase fw_version ஏத்தி புது .bin, illa USB)");
    Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
  } else {
    // இந்த boot fail ஆகலாம் nu முன்கூட்டி counter ஏத்து.
    // connect ஆனா commitHealthy() அத 0-ku reset பண்ணும்.
    bootFailIncrement();
  }

  pinMode(CH1, OUTPUT);
  pinMode(CH2, OUTPUT);
  digitalWrite(CH1, relayState[0] ? HIGH : LOW);
  digitalWrite(CH2, relayState[1] ? HIGH : LOW);

  pinMode(BTN_CH1, INPUT_PULLUP);
  pinMode(BTN_CH2, INPUT_PULLUP);
  pinMode(BTN_WIFI, INPUT);

  // WiFiManager
  WiFiManager wm;
  wm.setConfigPortalTimeout(180);
  Serial.println("WiFi connecting (WiFiManager)...");
  Serial.printf(">> connect ஆகலனா phone-ல '%s' தேடு (pass: %s)\n",
                AP_NAME, AP_PASSWORD);

  bool ok = wm.autoConnect(AP_NAME, AP_PASSWORD);
  if (!ok) {
    if (safeMode) {
      // *** v14 FIX: safe mode-ல WiFi fail ஆனா restart பண்ணக்கூடாது ***
      // device offline-ஆ relay/button-ல உயிரோட இருக்கணும். restart loop வேண்டாம்.
      Serial.println(">> SAFE MODE + WiFi இல்ல -> OFFLINE. Relay/button வேலை செய்யும். NO restart.");
      return;   // setup முடி. loop() offline-ஆ ஓடும் (buttons மட்டும்).
    }
    Serial.println("WiFi fail/timeout -> restart");
    delay(1000);
    ESP.restart();
  }
  wifiUp = true;
  Serial.print("WiFi connected. IP: ");
  Serial.println(WiFi.localIP());

  /* ---- இங்க தான் முக்கியம்: Firebase-ku MUN cloud OTA ---- */
  doBootCloudOTA();

  // Local OTA
  setupOTA();
  localOtaReady = true;

  // Firebase
  config.api_key = API_KEY;
  config.database_url = DATABASE_URL;
  if (Firebase.signUp(&config, &auth, "", "")) {
    Serial.println("Firebase signUp OK");
    signupOK = true;
  } else {
    Serial.printf("signUp error: %s\n", config.signer.signupError.message.c_str());
  }
  config.token_status_callback = tokenStatusCallback;
  fbdo.setBSSLBufferSize(2048, 1024);
  fbdo.setResponseSize(1024);
  Firebase.begin(&config, &auth);
  Firebase.reconnectWiFi(true);

  // *** v14: இங்க commit பண்ணமாட்டேன். loop-ல 30 sec stable ஓடின பிறகு commit.
  //     (connect ஆனவுடனே commit பண்ணா, சீக்கிரம் crash ஆகற bad fw பிடிபடாது) ***

  // boot ஆனதும் ஒரு தரம் status எழுது (safe mode ஆனாலும்!)
  writeStatus();
  lastStatusPush = millis();

  Serial.println(">> Ready. v14 -- SAFE MODE FIX + STABLE-COMMIT + RESCUE");
  Serial.printf(">> Health commit-ku %lu sec stable ஓடணும்...\n", HEALTH_COMMIT_DELAY_MS/1000);
}

/* ---------- BOOT SYNC ---------- */
void bootSyncToFirebase() {
  bool ok1 = Firebase.RTDB.setBool(&fbdo, "/relay1", relayState[0]);
  bool ok2 = Firebase.RTDB.setBool(&fbdo, "/relay2", relayState[1]);
  if (ok1 && ok2) {
    bootSyncDone = true;
    lastBtnChange[0] = millis();
    lastBtnChange[1] = millis();
    Serial.printf(">> Boot state synced: CH1=%s CH2=%s\n",
                  relayState[0] ? "ON" : "OFF",
                  relayState[1] ? "ON" : "OFF");
  }
}

/* ---------- read from Firebase ---------- */
void readFromFirebase(int idx, int pin) {
  if (millis() - lastBtnChange[idx] < BTN_LOCK_MS) return;

  String path = (idx == 0) ? "/relay1" : "/relay2";
  if (Firebase.RTDB.getBool(&fbdo, path.c_str())) {
    fbFailCount = 0;
    bool val = fbdo.boolData();
    if (val != relayState[idx]) setRelay(idx, pin, val);
  } else {
    fbFailCount++;
    Serial.printf("   FB read fail (%d/%d): %s\n",
                  fbFailCount, FB_FAIL_LIMIT, fbdo.errorReason().c_str());
    if (fbFailCount >= FB_FAIL_LIMIT) {
      Serial.println(">> SSL/Firebase stuck -> ESP RESTART (auto-heal)");
      delay(500);
      ESP.restart();
    }
  }
}

/* ---------- channel button ---------- */
void checkButton(int btnPin, int idx, int relayPin) {
  if (digitalRead(btnPin) == LOW) {
    delay(50);
    if (digitalRead(btnPin) == LOW) {
      bool newVal = !relayState[idx];
      setRelay(idx, relayPin, newVal);
      lastBtnChange[idx] = millis();
      pushToFirebase(idx, newVal);
      Serial.printf("   (CH%d toggled by BUTTON)\n", idx + 1);
      while (digitalRead(btnPin) == LOW) { yield(); }
    }
  }
}

/* ---------- WiFi reset button (3s hold) ---------- */
void checkWifiButton() {
  if (digitalRead(BTN_WIFI) == LOW) {
    if (wifiBtnPressStart == 0) {
      wifiBtnPressStart = millis();
    } else if (millis() - wifiBtnPressStart > WIFI_RESET_HOLD_MS) {
      Serial.println("\n>> WiFi RESET! Setup mode-க்கு போகுது...");
      WiFiManager wm;
      wm.resetSettings();
      delay(500);
      ESP.restart();
    }
  } else {
    wifiBtnPressStart = 0;
  }
}

/* ==================================================================
   DIAGNOSTICS — device தன் status-ஐ Firebase /status-ல எழுதுது.
   Office-ல serial இல்லாம device health பாக்கலாம்.
     /status/fw         : இப்போ எந்த version
     /status/state      : normal / safe_mode
     /status/dl_fail    : download fail count (இப்போ)
     /status/bad_ver    : எந்த version bad nu mark ஆச்சு
     /status/boot_fail  : boot-fail counter
     /status/heap       : free heap (memory health)
     /status/rssi       : WiFi signal strength
     /status/ip         : device IP
     /status/uptime_s   : எத்தன விநாடி ஓடுது (restart ஆனா 0-ku போகும்)
   ================================================================== */
void writeStatus() {
  if (!Firebase.ready() || !signupOK) return;

  FirebaseJson js;
  js.set("fw",        FW_VERSION_NUM);
  js.set("state",     safeMode ? "safe_mode" : "normal");
  js.set("dl_fail",   (int)EEPROM.read(EE_DLFAIL_ADDR) == 0xFF ? 0 : (int)EEPROM.read(EE_DLFAIL_ADDR));
  int bv = EEPROM.read(EE_BADVER_ADDR);
  js.set("bad_ver",   bv == 0xFF ? 0 : bv);
  int bf = EEPROM.read(EE_BOOTFAIL_ADDR);
  js.set("boot_fail", bf == 0xFF ? 0 : bf);
  js.set("heap",      (int)ESP.getFreeHeap());
  js.set("rssi",      (int)WiFi.RSSI());
  js.set("ip",        WiFi.localIP().toString());
  js.set("uptime_s",  (int)(millis() / 1000));

  if (Firebase.RTDB.setJSON(&fbdo, "/status", &js)) {
    Serial.println(">> Status pushed to Firebase /status");
  } else {
    Serial.printf(">> Status push fail: %s\n", fbdo.errorReason().c_str());
  }
}

/* ==================================================================
   REMOTE RESCUE (v14) — safe mode-ல device இருந்தா, office-ல
   Firebase /rescue = true போட்டா -> safe mode clear + restart.
   (WiFi இருந்தா USB தேவை இல்ல. WiFi இல்லனா USB தான் வழி.)
   ================================================================== */
void checkRescue() {
  if (!Firebase.ready() || !signupOK) return;
  if (Firebase.RTDB.getBool(&fbdo, "/rescue")) {
    if (fbdo.boolData() == true) {
      Serial.println(">> RESCUE flag detect! Safe mode clear பண்றேன், restart...");
      EEPROM.write(EE_SAFEMODE_ADDR, 0x00);
      EEPROM.write(EE_BOOTFAIL_ADDR, 0);
      EEPROM.write(EE_DLFAIL_ADDR, 0);
      EEPROM.write(EE_BADVER_ADDR, 0xFF);
      EEPROM.commit();
      // rescue flag-ஐ false-ஆ மாத்து (திரும்ப loop ஆகாம)
      Firebase.RTDB.setBool(&fbdo, "/rescue", false);
      delay(1000);
      ESP.restart();
    }
  }
}

void loop() {
  if (localOtaReady) ArduinoOTA.handle();

#if DEBUG_BTN
  if (millis() - lastDbg > 500) {
    lastDbg = millis();
    Serial.printf("BTN12=%d BTN13=%d BTN16=%d\n",
                  digitalRead(BTN_CH1), digitalRead(BTN_CH2), digitalRead(BTN_WIFI));
  }
#endif

  checkButton(BTN_CH1, 0, CH1);
  checkButton(BTN_CH2, 1, CH2);
  checkWifiButton();

  if (!safeMode && Firebase.ready() && signupOK && !bootSyncDone) bootSyncToFirebase();

  /* ---------- CLOUD OTA check ---------- */
  if (!safeMode && Firebase.ready() && signupOK && bootSyncDone) {
    if (!firstCloudOtaDone && millis() > CLOUD_OTA_FIRST_DELAY_MS) {
      firstCloudOtaDone = true;
      lastCloudOtaCheck = millis();
      checkCloudOTA();
    } else if (firstCloudOtaDone &&
               millis() - lastCloudOtaCheck > CLOUD_OTA_INTERVAL_MS) {
      lastCloudOtaCheck = millis();
      checkCloudOTA();
    }
  }

  // ---------- STABLE HEALTH COMMIT (v14) ----------
  // 30 sec stable ஓடி, WiFi+Firebase OK ஆனா தான் "healthy" nu commit.
  if (!safeMode && !healthCommitted && Firebase.ready() && signupOK &&
      millis() > HEALTH_COMMIT_DELAY_MS) {
    commitHealthy();
  }

  // ---------- periodic status push + rescue check (safe mode-லயும் ஓடும்) ----------
  if (Firebase.ready() && signupOK &&
      millis() - lastStatusPush > STATUS_PUSH_INTERVAL_MS) {
    lastStatusPush = millis();
    writeStatus();
    checkRescue();
  }

  if (!safeMode && Firebase.ready() && signupOK && bootSyncDone &&
      (millis() - lastRead > 500 || lastRead == 0)) {
    lastRead = millis();
    readFromFirebase(0, CH1);
    readFromFirebase(1, CH2);
  }
}
