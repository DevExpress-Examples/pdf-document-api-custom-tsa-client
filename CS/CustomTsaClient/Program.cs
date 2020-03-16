using DevExpress.Pdf;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.IO;
using System.Diagnostics;

namespace CustomTsaClient
{
    static class Program
    {
        static void Main(string[] args)
        {
            using (var signer = new PdfDocumentSigner(@"Document.pdf"))
            {
                //Create a custom timestamp client instance:
                ITsaClient tsaClient = new BouncyCastleTsaClient(new Uri(@"http://timestamp.apple.com/ts01"), new Sha256Digest());

                //Create a PKCS#7 signature:
                Pkcs7Signer pkcs7Signature = new Pkcs7Signer(@"testcert.pfx", "123", PdfHashAlgorithm.SHA256, tsaClient);                
                
                //Apply the signature to the form field:
                var signatureBuilder = new PdfSignatureBuilder(pkcs7Signature, "Sign");
                
                //Specify image data and signer information:
                signatureBuilder.SetImageData(File.ReadAllBytes("JaneCooper.jpg"));
                signatureBuilder.Location = "United Kingdom";
                
                //Sign and save the document:
                signer.SaveDocument("SignedDocument.pdf", signatureBuilder);
                Process.Start("SignedDocument.pdf");
            }
            return;
        }
    }
}
