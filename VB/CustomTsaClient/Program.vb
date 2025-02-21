Option Infer On

Imports DevExpress.Pdf
Imports DevExpress.Office.DigitalSignatures
Imports DevExpress.Office.Tsp
Imports Org.BouncyCastle.Crypto.Digests
Imports System
Imports System.IO
Imports System.Diagnostics

Namespace CustomTsaClient
	Friend Module Program
		Sub Main(ByVal args() As String)
			Using signer = New PdfDocumentSigner("Document.pdf")
				'Create a custom timestamp client instance:
				Dim tsaClient As ITsaClient = New BouncyCastleTsaClient(New Uri("https://freetsa.org/tsr"), New Sha256Digest(), New System.Net.Http.HttpClient())

				'Create a PKCS#7 signature:
				Dim pkcs7Signature As New Pkcs7Signer("testcert.pfx", "123", HashAlgorithmType.SHA256, tsaClient)

				'Apply the signature to the form field:
				Dim signatureBuilder = New PdfSignatureBuilder(pkcs7Signature, "Sign")

				'Specify image data and signer information:
				signatureBuilder.SetImageData(File.ReadAllBytes("JaneCooper.jpg"))
				signatureBuilder.Location = "United Kingdom"

				'Sign and save the document:
				signer.SaveDocument("SignedDocument.pdf", signatureBuilder)

			End Using
			Process.Start(New ProcessStartInfo("SignedDocument.pdf") With {.UseShellExecute = True})
			Return
		End Sub
	End Module
End Namespace
