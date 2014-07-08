using EU.Europa.EC.Markt.Dss;
using EU.Europa.EC.Markt.Dss.Signature;
using EU.Europa.EC.Markt.Dss.Signature.Cades;
using EU.Europa.EC.Markt.Dss.Signature.Token;
using EU.Europa.EC.Markt.Dss.Validation.Tsp;
using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Xamples
{
    class Program
    {
        static void Main(string[] args)
        {
            //Call to diferent Signature Standars.
            //XampleFirmaCadesT();
            XampleFirmaPades_CMS();
        }

        static void XampleFirmaCadesT()
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
            EU.Europa.EC.Markt.Dss.Signature.Document toSign = new InMemoryDocument(InMemoryDocument.StringToBytes("Hello World")); 
            //Tambiem podemos probar con un FileDocument.
            //Document toSign = new FileDocument("d:\\prueba\\rfc3161.pdf"); 
            
            SignatureParameters parameters = new SignatureParameters();
            CAdESService service = new CAdESService();
            parameters.SignaturePackaging = SignaturePackaging.ENVELOPING;
            //parameters.SignaturePackaging = SignaturePackaging.ENVELOPED;
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
            EU.Europa.EC.Markt.Dss.Signature.Document signedDocument = service.SignDocument(toSign, parameters, signatureValue);
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

        static void XampleFirmaPades_CMS()
        {
            X509Certificate2 mycert = CertStoreWrapper.GetCertificateBySubject("CN=NOMBRE LOPEZ DE ELORRIAGA PRIETO JESUS EUGENIO - NIF 50458098P, OU=500690145, OU=FNMT Clase 2 CA, O=FNMT, C=ES");
            PdfReader reader = new PdfReader("D:\\prueba\\rfc3161.pdf");
            using (FileStream os = new FileStream("D:\\prueba\\rfc3161_firmado_CADES.pdf", FileMode.Create))
            {
                using (PdfStamper stamper = PdfStamper.CreateSignature(reader, os, '\0'))
                {
                    PdfSignatureAppearance appearance = stamper.SignatureAppearance;

                    appearance.Reason = "Pruebas Cades CMS";
                    appearance.Location = "Madrid";
                    appearance.SetVisibleSignature(new Rectangle(36, 748, 144, 780), 1, "signature");
                    // Creating the signature
                    //AsymmetricKeyParameter akp = Org.BouncyCastle.Security.DotNetUtilities.GetKeyPair(mycert.PrivateKey).Private;
                    //IExternalSignature es = new PrivateKeySignature(mycert, "SHA-256");
                    IExternalSignature es = new X509Certificate2Signature(mycert, "SHA-1");
                    ICollection<Org.BouncyCastle.X509.X509Certificate> chain = new List<Org.BouncyCastle.X509.X509Certificate>();
                    X509Chain x509chain = new X509Chain();
                    x509chain.Build(mycert);

                    foreach (X509ChainElement x509ChainElement in x509chain.ChainElements)
                    {
                        chain.Add(Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(x509ChainElement.Certificate));
                    }

                    MakeSignature.SignDetached(appearance, es, chain, null, null, null, 0, CryptoStandard.CADES);
                    stamper.Close();
                }
                
            }
            
            
            
        }
    
    }
}
