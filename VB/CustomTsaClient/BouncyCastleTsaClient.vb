Imports DevExpress.Pdf
Imports Org.BouncyCastle.Asn1.Cmp
Imports Org.BouncyCastle.Crypto
Imports Org.BouncyCastle.Crypto.Digests
Imports Org.BouncyCastle.Math
Imports Org.BouncyCastle.Security
Imports Org.BouncyCastle.Tsp
Imports System
Imports System.IO
Imports System.Net
Imports System.Security.Cryptography
Imports System.Diagnostics

Namespace CustomTsaClient
	Public Class BouncyCastleTsaClient
		Implements ITsaClient

		Private ReadOnly tsaServerURI As Uri

		Private ReadOnly hashCalculator As IDigest

		Public Sub New(ByVal tsaServerURI As Uri, ByVal hashCalculator As IDigest)
			Me.tsaServerURI = tsaServerURI
			Me.hashCalculator = hashCalculator
		End Sub
		Private Function CalculateDigest(ByVal stream As Stream) As Byte()
			Dim buffer(81919) As Byte
			hashCalculator.Reset()
			Dim bytesRead As Integer
'INSTANT VB WARNING: An assignment within expression was extracted from the following statement:
'ORIGINAL LINE: while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
			bytesRead = stream.Read(buffer, 0, buffer.Length)
			Do While bytesRead > 0
				hashCalculator.BlockUpdate(buffer, 0, bytesRead)
				bytesRead = stream.Read(buffer, 0, buffer.Length)
			Loop
			Dim result(hashCalculator.GetDigestSize() - 1) As Byte
			hashCalculator.DoFinal(result, 0)
			Return result
		End Function

		Public Function GenerateTimeStamp(ByVal stream As Stream) As Byte()
			'Generate a timestamp request:
			Dim tsqGenerator As New TimeStampRequestGenerator()
			tsqGenerator.SetCertReq(True)
			Dim nonce As BigInteger
			Using generator As RandomNumberGenerator = RandomNumberGenerator.Create()
				Dim nonceValue(9) As Byte
				generator.GetBytes(nonceValue)
				nonce = New BigInteger(nonceValue)
			End Using
			Dim algorithmOid As String = DigestUtilities.GetObjectIdentifier(hashCalculator.AlgorithmName).Id
			Dim request As TimeStampRequest = tsqGenerator.Generate(algorithmOid, CalculateDigest(stream), nonce)
			Dim requestBytes() As Byte = request.GetEncoded()

			'Send the request to a server:
			Dim httpRequest As HttpWebRequest = CType(WebRequest.Create(tsaServerURI), HttpWebRequest)
			httpRequest.Method = "POST"
			httpRequest.ContentType = "application/timestamp-query"
			httpRequest.ContentLength = requestBytes.Length
			Using requestStream As Stream = httpRequest.GetRequestStream()
				requestStream.Write(requestBytes, 0, requestBytes.Length)
			End Using

			'Get a response from the server:
			Dim httpResponse As HttpWebResponse = CType(httpRequest.GetResponse(), HttpWebResponse)
			Using respStream As Stream = New BufferedStream(httpResponce.GetResponseStream())
				'Read the responce:
				Dim response As New TimeStampResponse(respStream)
				response.Validate(request)
				Dim failure As PkiFailureInfo = response.GetFailInfo()

				'Throw an exception if the responce returned an error:                
				If failure IsNot Nothing Then
					Throw New Exception($"TimeStamp request to the ""{tsaServerURI}"" failed.")
				End If
				Dim token As TimeStampToken = response.TimeStampToken

				'Throw an exception if the responce doesn't contain the timestamp:
				If token Is Nothing Then
					Throw New Exception($"TimeStamp request to the ""{tsaServerURI}"" failed.")
				End If
				Return token.GetEncoded()
			End Using
		End Function
	End Class

End Namespace
