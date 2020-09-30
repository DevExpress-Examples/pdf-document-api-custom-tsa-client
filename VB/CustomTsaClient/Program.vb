Imports DevExpress.Pdf
Imports DevExpress.Office.Tsp
Imports Org.BouncyCastle.Crypto.Digests
Imports System
Imports System.IO
Imports System.Diagnostics
Imports DevExpress.Office.DigitalSignatures

Namespace CustomTsaClient
    Friend NotInheritable Class Program

        Private Sub New()
        End Sub

        Shared Sub Main(ByVal args() As String)
            Using signer = New PdfDocumentSigner("Document.pdf")
                'Create a custom timestamp client instance:
                Dim tsaClient As ITsaClient = New BouncyCastleTsaClient(New Uri("https://freetsa.org/tsr"), New Sha256Digest())

                'Create a PKCS#7 signature:
                Dim pkcs7Signature As New Pkcs7Signer("testcert.pfx", "123", HashAlgorithmType.SHA256, tsaClient)

                'Apply the signature to the form field:
                Dim signatureBuilder = New PdfSignatureBuilder(pkcs7Signature, "Sign")

                'Specify image data and signer information:
                signatureBuilder.SetImageData(File.ReadAllBytes("JaneCooper.jpg"))
                signatureBuilder.Location = "United Kingdom"

                'Sign and save the document:
                signer.SaveDocument("SignedDocument.pdf", signatureBuilder)
                Process.Start("SignedDocument.pdf")
            End Using
            Return
        End Sub
    End Class
End Namespace
