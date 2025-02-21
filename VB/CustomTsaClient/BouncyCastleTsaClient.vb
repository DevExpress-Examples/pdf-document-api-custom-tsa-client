Imports DevExpress.Office.Tsp
Imports Org.BouncyCastle.Asn1.Cmp
Imports Org.BouncyCastle.Crypto
Imports Org.BouncyCastle.Math
Imports Org.BouncyCastle.Security
Imports Org.BouncyCastle.Tsp
Imports System
Imports System.IO
Imports System.Net.Http
Imports System.Security.Cryptography

Public Class BouncyCastleTsaClient
    Implements ITsaClient

    Private ReadOnly tsaServerURI As Uri
    Private ReadOnly hashCalculator As IDigest
    Private ReadOnly httpClient As HttpClient

    Public Sub New(tsaServerURI As Uri, hashCalculator As IDigest, httpClient As HttpClient)
        Me.tsaServerURI = tsaServerURI
        Me.hashCalculator = hashCalculator
        Me.httpClient = httpClient
    End Sub

    Private Function CalculateDigest(stream As Stream) As Byte()
        Dim buffer(81919) As Byte
        hashCalculator.Reset()
        Dim bytesRead As Integer
        Do
            bytesRead = stream.Read(buffer, 0, buffer.Length)
            If bytesRead > 0 Then
                hashCalculator.BlockUpdate(buffer, 0, bytesRead)
            End If
        Loop While bytesRead > 0
        Dim result(hashCalculator.GetDigestSize() - 1) As Byte
        hashCalculator.DoFinal(result, 0)
        Return result
    End Function

    Public Function GenerateTimeStamp(stream As Stream) As Byte() Implements ITsaClient.GenerateTimeStamp
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
        Dim requestBytes As Byte() = request.GetEncoded()

        Using content As New ByteArrayContent(requestBytes)
            content.Headers.ContentType = New System.Net.Http.Headers.MediaTypeHeaderValue("application/timestamp-query")
            Using responseMessage As HttpResponseMessage = httpClient.PostAsync(tsaServerURI, content).Result
                If Not responseMessage.IsSuccessStatusCode Then
                    Throw New Exception($"TimeStamp request to ""{tsaServerURI}"" failed with status code {responseMessage.StatusCode}.")
                End If
                Dim responseBytes As Byte() = responseMessage.Content.ReadAsByteArrayAsync().Result
                Dim response As New TimeStampResponse(responseBytes)
                response.Validate(request)
                Dim failure As PkiFailureInfo = response.GetFailInfo()
                If failure IsNot Nothing Then
                    Throw New Exception($"TimeStamp request to the ""{tsaServerURI}"" failed.")
                End If
                Dim token As TimeStampToken = response.TimeStampToken
                If token Is Nothing Then
                    Throw New Exception($"TimeStamp request to ""{tsaServerURI}"" failed.")
                End If
                Return token.GetEncoded()
            End Using
        End Using
    End Function

    Public Function GenerateTimeStamp(digest As Byte(), digestAlgorithmOID As String) As Byte() Implements ITsaClient.GenerateTimeStamp
        Dim tsqGenerator As New TimeStampRequestGenerator()
        tsqGenerator.SetCertReq(True)
        Dim nonce As BigInteger
        Using generator As RandomNumberGenerator = RandomNumberGenerator.Create()
            Dim nonceValue(9) As Byte
            generator.GetBytes(nonceValue)
            nonce = New BigInteger(nonceValue)
        End Using
        Dim algorithmOid As String = DigestUtilities.GetObjectIdentifier(hashCalculator.AlgorithmName).Id
        Dim request As TimeStampRequest = tsqGenerator.Generate(algorithmOid, digest, nonce)
        Dim requestBytes As Byte() = request.GetEncoded()

        Using content As New ByteArrayContent(requestBytes)
            content.Headers.ContentType = New System.Net.Http.Headers.MediaTypeHeaderValue("application/timestamp-query")
            Using responseMessage As HttpResponseMessage = httpClient.PostAsync(tsaServerURI, content).Result
                If Not responseMessage.IsSuccessStatusCode Then
                    Throw New Exception($"TimeStamp request to ""{tsaServerURI}"" failed with status code {responseMessage.StatusCode}.")
                End If
                Dim responseBytes As Byte() = responseMessage.Content.ReadAsByteArrayAsync().Result
                Dim response As New TimeStampResponse(responseBytes)
                response.Validate(request)
                Dim failure As PkiFailureInfo = response.GetFailInfo()
                If failure IsNot Nothing Then
                    Throw New Exception($"TimeStamp request to ""{tsaServerURI}"" failed.")
                End If
                Dim token As TimeStampToken = response.TimeStampToken
                If token Is Nothing Then
                    Throw New Exception($"TimeStamp request to ""{tsaServerURI}"" failed.")
                End If
                Return token.GetEncoded()
            End Using
        End Using
    End Function

End Class
