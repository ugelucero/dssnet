using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Xamples
{
   
    public static class CertStoreWrapper
    {
        public static IEnumerable<X509Certificate2> GetFnmtCertificates()
        {
            var certificates = new List<X509Certificate2>();
            X509Store store = new X509Store(StoreName.My);
            store.Open(OpenFlags.ReadOnly);
            foreach (X509Certificate2 certificate in store.Certificates)
            {
                //O=FNMT, C=ES is a filtering system for FNMT certificates
                var issuerName = certificate.IssuerName.Name;
                if (!issuerName.Contains("O=FNMT"))
                    continue;

                certificates.Add(certificate);
            }
            store.Close();
            return certificates;
        }

        public static X509Certificate2 GetCertificateBySubject(string subject)
        {
            if (string.IsNullOrEmpty(subject))
                throw new ArgumentException("subject");

            var certificate = GetFnmtCertificates().SingleOrDefault(c => c.Subject == subject);
            if (null == certificate)
                throw new ArgumentException("No hay firma con subject:" + subject);

            return certificate;
        }
    }
}
