using EU.Europa.EC.Markt.Dss;
using EU.Europa.EC.Markt.Dss.Signature;
using EU.Europa.EC.Markt.Dss.Signature.Cades;
using EU.Europa.EC.Markt.Dss.Signature.Token;
using EU.Europa.EC.Markt.Dss.Validation.Tsp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Xamples
{
    class Program
    {
        static void Main(string[] args)
        {
            // Create a token connection based on a pkcs12 file commonly used to store private
            // keys with accompanying public key certificates, protected with a password-based
            // symmetric key.
            //SEguramente deba poder conseguir del almacen el certificado usando KSX509Certificate2Entry o MSCAPISignatureToken (el cert en estos es el de Micro).
            //AsyncSignatureTokenConnection token = new Pkcs12SignatureToken("password", "pkcs12TokenFile");
            
            MSCAPISignatureToken token = new MSCAPISignatureToken();
            token.Cert = CertStoreWrapper.GetCertificateBySubject("CN=NOMBRE LOPEZ DE ELORRIAGA PRIETO JESUS EUGENIO - NIF 50458098P, OU=500690145, OU=FNMT Clase 2 CA, O=FNMT, C=ES");
            //token.Cert = new System.Security.Cryptography.X509Certificates.X509Certificate2();
            //A comentar
            IDssPrivateKeyEntry privateKey = token.GetKeys().First();
            Document toSign = new InMemoryDocument(InMemoryDocument.StringToBytes("Hello World")); 
            //Tambiem podemos probar con un FileDocument.
            
            SignatureParameters parameters = new SignatureParameters();
            CAdESService service = new CAdESService();
            parameters.SignaturePackaging = SignaturePackaging.ENVELOPING;
            parameters.SignatureFormat=SignatureFormat.CAdES_T;
            parameters.SigningCertificate = privateKey.GetCertificate();
            parameters.CertificateChain = privateKey.GetCertificateChain();
            parameters.SigningDate = DateTime.Now;
            parameters.DigestAlgorithm = DigestAlgorithm.SHA1;

            //Buscar TSPs como:
            //http://services.globaltrustfinder.com/adss/tsa o 
            //http://tsa.safecreative.org (5 gratis al día).
            service.TspSource = new OnlineTspSource("http://tsa.safecreative.org");//Por ejemplo.
            System.IO.Stream signedStream = service.ToBeSigned(toSign, parameters);
            byte[] signatureValue = token.Sign(signedStream, parameters.DigestAlgorithm, privateKey);
            Document signedDocument = service.SignDocument(toSign, parameters, signatureValue);
            System.IO.Stream stream = signedDocument.OpenStream();
            byte[] signedArray = new byte[stream.Length];
            stream.Read(signedArray,0,(int)stream.Length);
            // A Fichero.
            System.IO.File.WriteAllBytes("D:\\PRUEBA\\sal.bin", signedArray);
            string Salida = InMemoryDocument.BytesToString(signedArray);
            //signedDocument.OpenStream()
            Console.WriteLine(Salida);
            Console.ReadLine();
        }
    }
}
