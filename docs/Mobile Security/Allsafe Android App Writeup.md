# ALLSAFE Android App WriteUp Part 1

Merhabalar, bu yazımda [allsafe][3] zafiyetli mobil uygulaması anlatacağım.

Apk dosyasını emülatöre yükleyip açtığımızda bizi yukarıdaki ekran karşılıyor.

Ve apk dosyasının kaynak kodlarına ulaşmak için [jadx-gui][4] aracını kullanıyorum.

## **Zafiyet Adı** : Insecure Logging

**Zafiyet Tanımı** : Insecure Logging zafiyeti, uygulamanın kullanıcıya veya sisteme ait hassas verileri log dosyalarına kaydetmesi ve bu verilerin yetkisiz kişiler tarafından okunabilir hale gelmesidir.

**Zafiyet Derecesi** : Orta --- Kritik

Hassas verinin türüne bağlıdır:

Eğer parola, token, kredi kartı bilgisi, sağlık verisi gibi kritik bilgiler loglara düşüyorsa → Yüksek Risk

Eğer sadece kullanıcı adı, cihaz bilgisi, hata kodları gibi görece daha az hassas bilgiler loglanıyorsa → Orta Risk

Logcat'i açıp buraya "The secret text is here." yazıp enter'a bastığımızda yazdığımız yazının aşağıdaki gibi loglara düştüğünü göreceksiniz.

Press enter or click to view image in full size

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

## Zafiyet Adı : Hardcoded Credentials

**Zafiyet Tanımı** : Hardcoded Credentials zafiyeti, bir uygulamanın kaynak kodu içerisinde kullanıcı adı, parola, API anahtarı, erişim tokeni, şifreleme anahtarı gibi kimlik doğrulama veya yetkilendirme bilgilerini sabit (hardcode) olarak barındırması durumudur. Bu bilgiler genellikle uygulama paketinin tersine mühendislik (reverse engineering) yoluyla açığa çıkarılabilir. Sonuç olarak saldırgan, bu kimlik bilgilerini ele geçirerek uygulamanın arka uç servislerine, veritabanına veya üçüncü taraf sistemlere yetkisiz erişim sağlayabilir.

**Zafiyet Derecesi** : Orta --- Yüksek

Kritik sistemlere erişim sağlayan kimlik bilgileri (ör. veritabanı parolası, production API anahtarı) kod içerisinde sabitlenmişse. → Yüksek Risk

Saldırganın erişmesi durumunda sınırlı etkiye sahip test/demonstrasyon amaçlı kimlik bilgileri kodda bulunuyorsa. → Orta Risk

username:password şeklinde kaynak kodunda kimlik bilgileri bulunduğunu söylüyor. Butona tıkladığımızda "Under development!" uyarısı ile karşılaşıyoruz.

    public static final void onCreateView$lambda$0(HardcodedCredentials this$0, View it) {
            OkHttpClient client = new OkHttpClient();
            RequestBody body = RequestBody.INSTANCE.create(BODY, SOAP);
            Request.Builder builder = new Request.Builder();
            String string = this$0.getString(R.string.dev_env);
            Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
            Request req = builder.string.post(body).build();
            client.newCall(req).enqueue(new Callback() { // from class: infosecadventures.allsafe.challenges.HardcodedCredentials$onCreateView$1$1
                @Override // okhttp3.Callback
                public void onResponse(Call call, Response response) {
                    Intrinsics.checkNotNullParameter(call, "call");
                    Intrinsics.checkNotNullParameter(response, "response");
                }@Override // okhttp3.Callback
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

Kaynak kodunu incelediğimizda aşağıdaki satır dikkatimizi çekiyor. Çünkü uygulamadaki uyarı da "Under development!" diyordu. Yani development'ın kısaltması "dev".

    String string = this$0.getString(R.string.dev_env);

`R.string.dev_env` → `res/values/strings.xml` dosyasında tanımlı olan `dev_env` string resource'unun ID'sidir.

strings.xml dosyasına gidip dev_env stringinin karşılığına bakalım.

Press enter or click to view image in full size

Söylediği username:password 'ün karşılığı "admin:password123" imiş.

## **Zafiyet Adı : Firebase Database**

**Zafiyet Tanımı** : Firebase Database zafiyeti, geliştiricilerin Firebase Realtime Database veya Firestore yapılandırmalarında gerekli erişim kontrolünü sağlamaması sonucu ortaya çıkar. Firebase Realtime Database, URL'ye `.json` eklenerek erişilebilen bir REST API olarak çalışır; eğer read/write kuralları "anyone" (herkes) erişimine açık bırakılırsa, kimliği doğrulanmamış saldırganlar veritabanına doğrudan erişebilir. Bu durum, verilerin izinsiz okunması, değiştirilmesi veya silinmesi gibi ciddi güvenlik açıklarına yol açar. Bu durum saldırgana:
- Kullanıcı bilgilerini (e-posta, telefon, adres, şifre hashleri vb.) okuma,
- Veritabanındaki kayıtları değiştirme veya silme,
- Yeni sahte kullanıcı/veri ekleme,
- Uygulamanın işleyişini manipüle etme imkânı verir.

Bu zafiyet genellikle mobil uygulamaların tersine mühendislik (reverse engineering) yoluyla Firebase endpoint adresinin çıkarılması ve ardından yanlış yapılandırılmış veritabanına doğrudan erişim sağlanmasıyla istismar edilir.

**Zafiyet Derecesi** : Orta --- Yüksek --- Kritik

Veritabanında kullanıcı bilgileri, ödeme bilgileri, kimlik doğrulama verileri gibi hassas veriler bulunuyorsa. → Yüksek Risk

Hem okuma hem yazma izinleri herkese açıksa → kullanıcı hesaplarının ele geçirilmesi, veritabanının tamamen manipüle edilmesi mümkün olur. → Kritik Risk

Yalnızca kısıtlı ve düşük hassasiyete sahip veriler açığa çıkıyorsa. → Orta Risk

Kaynak kodu inceleyelim.

Press enter or click to view image in full size

Kaynak kodu incelerken firebase adında tüm kodlarda arama yaptığımda yukarıdaki işaretlediğim satıra denk geldim. Bu satır, Android'in derleyici tarafından otomatik oluşturulan bir kaynak ID'sini temsil etmektedir. Bu ID, uygulamadaki bir string, layout veya drawable kaynağına karşılık gelir.

string.xml dosyasına gidelim ve firebase adına bir arama yapalım.

Press enter or click to view image in full size

Kaynak kodunda görüldüğü üzere firebase database'e ait url adresi string.xml içerisine koyulmuş.

Press enter or click to view image in full size

Görüldüğü üzere konfigürasyon hatasından kaynaklı olarak url adresinin sonuna .json koyulduğunda ilgili endpointe ulaşılabiliniyor.

## Zafiyet Adı : Insecure Shared Preferences

**Zafiyet Tanımı** : Insecure Shared Preferences zafiyeti, Android uygulamalarının SharedPreferences mekanizmasını kullanarak hassas verileri (örneğin kullanıcı adı, parola, token, API anahtarı, kredi kartı bilgisi vb.) şifrelenmeden veya yeterli erişim kontrolü olmadan depolaması durumunda ortaya çıkar. Bu veriler, cihaz root edilmişse veya kötü amaçlı bir uygulama cihazda çalıştırılmışsa kolayca erişilebilir, okunabilir ve manipüle edilebilir. Bu durum kullanıcı verilerinin çalınmasına, kimlik doğrulama bypass'ına veya hesapların ele geçirilmesine yol açabilir.

**Zafiyet Derecesi** : Yüksek

Burada bir kullanıcı adı ve şifre belirleyip bu bilgileri saklamak için butona basıyorum.

Ardından ilgili verilerin şifreli mi şifresiz mi saklandığını belirlemek için terminal üzerinden ilgili konuma gidiyorum.

Press enter or click to view image in full size

Görüldüğü üzere şifresiz bir şekilde saklanıyorlar.

## Zafiyet Adı : SQL Injection

**Zafiyet Tanımı** : SQL Injection zafiyeti, bir uygulamanın kullanıcıdan aldığı veri üzerinde yeterli doğrulama veya filtreleme yapmadan SQL sorgularına doğrudan dahil etmesi durumunda ortaya çıkar. Saldırgan, özel olarak hazırlanmış girişler (payload) kullanarak veritabanına yetkisiz erişim sağlayabilir, veri sızıntısı yaratabilir, verileri değiştirebilir veya silebilir, hatta bazı durumlarda uygulamanın çalıştığı sunucu üzerinde komut çalıştırabilir. Bu zafiyet genellikle web uygulamaları, API'ler veya mobil uygulamaların backend servislerinde görülür.

**Zafiyet Derecesi** : Kritik

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

username : admin' or 1=1 ---

password : admin

Uygulama da girdi istenilen yerleri yukarıdaki gibi doldurduğumuzda:

Resimde görüldüğü gibi bütün kullanıcıların kullanıcı adı ve şifrelerini çekmiş bulunuyoruz.

    select * from user where username = 'admin' or 1=1 --' and password = 'admin'

Çünkü bizim gönderdiğimiz kullanıcı adı ve şifre sql komutunda bir manipülasyona yol açtı. Kullanıcı adını girdikten sonra "or 1=1 --- " şeklinde devam ettik. Burada 1=1 zaten doğru ve "or" ile kullanınca kullanıcı adı doğru olsa da olmasa da sorgu doğru olarak kabul edilecek ve " --- " (iki tire) sql sorgularında yorum satırı oluşturmak için kullanılır yani iki tireden sonraki sorgunun bir önemi kalmayacak bu şekilde sql komutunun tamamı doğru sonuç dönecek şekilde manipüle edecektir.

## Zafiyet Adı : PIN Bypass

**Zafiyet Tanımı** : PIN Bypass zafiyeti, bir uygulamanın veya cihazın kullanıcıya ait PIN (Personal Identification Number) doğrulamasını atlamaya veya atlatılabilir hale gelmesine izin veren bir güvenlik açığıdır. Bu zafiyet, kullanıcı kimliğinin yeterince doğrulanmaması, hatalı oturum yönetimi veya eksik güvenlik kontrolleri nedeniyle oluşabilir. Saldırgan, PIN doğrulamasını atlayarak uygulamaya veya cihazdaki hassas verilere yetkisiz erişim sağlayabilir.

**Zafiyet Derecesi** : Yüksek

Uygulamada görüldüğü üzere 4 karakterli bir PIN var. Bunu frida ile birkaç farklı şekilde bypass edebiliriz.

    private final boolean checkPin(String pin) {
            byte[] decode = Base64.decode("NDg2Mw==", 0);
            Intrinsics.checkNotNullExpressionValue(decode, "decode(...)");
            return Intrinsics.areEqual(pin, new String(decode, Charsets.UTF_8));
        }

Kaynak kodunu incelediğimizde checkPin adlı bir metod kullanarak PIN'i kontrol ettiğini görüyoruz. İstersek base64 ile şifrelenmiş metni çözerek PIN'e ulaşabiliriz. Ama öyle yapmayacağız onun yerine Frida kullanarak bir script yazıp o şekilde PIN'i bypass edeceğiz.

### Frida Script --- Senaryo 1

    Java.perform(function(){
        var pinBypass = Java.use("infosecadventures.allsafe.challenges.PinBypass");
        pinBypass.checkPin.implementation = function(pin){
            return true;
        }
    });

Yukarıda ilgili sınıfın ismini çağırdıktan sonra sınıfın içerisinde yer alan checkPin metodunu uygulama çalışırken hook'layıp dönülen değerin true olmasını sağladık. Bu sayede biz 4 karakterli ne girersek doğru diyecek ve bu şekilde bypass etmiş olacağız.

Press enter or click to view image in full size

Ve script'imizi çalıştırdık. Hiçbir hata vermedi.

Konsol çıktısında görüldüğü üzere 1234 girdim. Butona bastığımda gayet başarılı bir şekilde bypass ettiğimizi görüyoruz.

### Frida Bypass --- Senaryo 2

    Java.perform(function () {
        var PinBypass = Java.use("infosecadventures.allsafe.challenges.PinBypass");// Sınıftan bir örnek oluştur
        var pinInstance = PinBypass.$new();// Brute-force 1111 -> 9999
        for (var i = 1111; i <= 9999; i++) {
            var pin = i.toString();
            var res = pinInstance.checkPin(pin);
            if (res) {
                console.log("[*] PIN: " + pin);
                break; 
            }
        }
    });

Yukarıdaki script koduyla ilgili PIN'i bulmak için brute-froce saldırısı yapmayı amaçladık. Bulduktan sonra PIN'i konsola bastık.

Önce sınıfı çağırdık. Sınıftan bir nesne oluşturduktan sonra checkPin metoduna 1111'ten başlayıp 9999'a kadar giden PIN'leri denedik. Bu sayede metottan doğru PIN'i çektik.

Press enter or click to view image in full size

Doğru PIN : 4863 imiş.

Görüldüğü üzere yine başarılı bir şekilde bypass ettik.

## Zafiyet Adı : Root Detection Bypass

**Zafiyet Tanımı** : Root Detection Bypass zafiyeti, Android uygulamalarında geliştiriciler tarafından cihazın rootlu olup olmadığını tespit etmek için eklenen kontrollerin saldırgan tarafından atlatılması durumudur. Normal şartlarda root edilmiş cihazlarda uygulamanın çalışması engellenmeli veya güvenlik seviyeleri artırılmalıdır. Ancak bu kontrollerin zayıf veya yanlış uygulanması, saldırganların uygulamanın root tespit mekanizmasını manipüle ederek rootlu cihazlarda çalıştırmasına ve böylece güvenlik önlemlerini devre dışı bırakmasına neden olur. Bu durum, saldırganların uygulamayı tersine mühendislik ile analiz etmesini, bellek manipülasyonu yapmasını veya hassas verileri daha kolay elde etmesini mümkün kılar.

**Zafiyetin Derecesi** : Orta

Root detection bypass tek başına doğrudan veri sızıntısına sebep olmasa da, uygulamanın güvenlik mekanizmalarının devre dışı bırakılmasına ve ileri seviye saldırıların (ör. kod enjeksiyonu, trafik manipülasyonu, hassas veri hırsızlığı) kolaylaşmasına yol açtığı için **orta seviye** bir güvenlik riski olarak değerlendirilir.

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

Biz frida ile isRooted() fonksiyonunu hook'layıp return değerini daima false olacak şekilde ayarlayacağız.

    Java.perform(function () {
        var rootDetection = Java.use("com.scottyab.rootbeer.RootBeer")
        rootDetection.isRooted.implementation = function(){
            return false;
        }
    });

Script'imizi yazdık. Şimdi çalıştıralım.

Press enter or click to view image in full size

Sorunsuz çalıştı.

Görüldüğü üzere root detection mekanizmasını bypass etmeyi başardık.

  [1]: https://medium.com/@emirec?source=post_page---byline--d93e4d24708d---------------------------------------
  [2]: https://miro.medium.com/v2/resize:fill:64:64/1*Inp_h8gYN02E5EXuWSU0tg.jpeg
  [3]: https://github.com/t0thkr1s/allsafe-android/releases/download/v1.5/allsafe.apk
  [4]: https://sourceforge.net/projects/jadx.mirror/
