using DevExpress.Office.Tsp;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;

public class BouncyCastleTsaClient : ITsaClient
{
    readonly Uri tsaServerURI;

    readonly IDigest hashCalculator;

    readonly HttpClient httpClient;

    public BouncyCastleTsaClient(Uri tsaServerURI, IDigest hashCalculator, HttpClient httpClient)
    {
        this.tsaServerURI = tsaServerURI;
        this.hashCalculator = hashCalculator;
        this.httpClient = httpClient;
    }
    byte[] CalculateDigest(Stream stream)
    {
        byte[] buffer = new byte[81920];
        hashCalculator.Reset();
        int bytesRead;
        while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
            hashCalculator.BlockUpdate(buffer, 0, bytesRead);
        byte[] result = new byte[hashCalculator.GetDigestSize()];
        hashCalculator.DoFinal(result, 0);
        return result;
    }

    public byte[] GenerateTimeStamp(Stream stream)
    {
        //Generate a timestamp request:
        TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
        tsqGenerator.SetCertReq(true);
        BigInteger nonce;
        using (RandomNumberGenerator generator = RandomNumberGenerator.Create())
        {
            byte[] nonceValue = new byte[10];
            generator.GetBytes(nonceValue);
            nonce = new BigInteger(nonceValue);
        }
        string algorithmOid = DigestUtilities.GetObjectIdentifier(hashCalculator.AlgorithmName).Id;
        TimeStampRequest request = tsqGenerator.Generate(algorithmOid, CalculateDigest(stream), nonce);
        byte[] requestBytes = request.GetEncoded();

        //Send the request to a server:
        HttpClient httpClient = new HttpClient();
        using var content = new ByteArrayContent(requestBytes);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/timestamp-query");
        //Get a responce from the server:
        using HttpResponseMessage responseMessage = httpClient.PostAsync(tsaServerURI, content).Result;
        if (!responseMessage.IsSuccessStatusCode)
        {
            throw new Exception($"TimeStamp request to the \"{tsaServerURI}\" failed with status code {responseMessage.StatusCode}.");
        }
        byte[] responseBytes = responseMessage.Content.ReadAsByteArrayAsync().Result;
        //Read the response:
        TimeStampResponse response = new TimeStampResponse(responseBytes);
        response.Validate(request);
        PkiFailureInfo failure = response.GetFailInfo();

        //Throw an exception if the responce returned an error:                
        if (failure != null)
            throw new Exception($"TimeStamp request to the \"{tsaServerURI}\" failed.");
        TimeStampToken token = response.TimeStampToken;

        //Throw an exception if the responce doesn't contain the timestamp:
        if (token == null)
            throw new Exception($"TimeStamp request to the \"{tsaServerURI}\" failed.");
        return token.GetEncoded();
    }

    public byte[] GenerateTimeStamp(byte[] digest, string digestAlgorithmOID)
    {
        //Generate a timestamp request:
        TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
        tsqGenerator.SetCertReq(true);
        BigInteger nonce;
        using (RandomNumberGenerator generator = RandomNumberGenerator.Create())
        {
            byte[] nonceValue = new byte[10];
            generator.GetBytes(nonceValue);
            nonce = new BigInteger(nonceValue);
        }
        string algorithmOid = DigestUtilities.GetObjectIdentifier(hashCalculator.AlgorithmName).Id;
        TimeStampRequest request = tsqGenerator.Generate(algorithmOid, digest, nonce);
        byte[] requestBytes = request.GetEncoded();

        //Send the request to a server:
        HttpClient httpClient = new HttpClient();
        using var content = new ByteArrayContent(requestBytes);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/timestamp-query");
        //Get a responce from the server:
        using HttpResponseMessage responseMessage = httpClient.PostAsync(tsaServerURI, content).Result;
        if (!responseMessage.IsSuccessStatusCode)
        {
            throw new Exception($"TimeStamp request to the \"{tsaServerURI}\" failed with status code {responseMessage.StatusCode}.");
        }
        byte[] responseBytes = responseMessage.Content.ReadAsByteArrayAsync().Result;

        //Read the response:
        TimeStampResponse response = new TimeStampResponse(responseBytes);
        response.Validate(request);
        PkiFailureInfo failure = response.GetFailInfo();


        //Throw an exception if the responce returned an error:                
        if (failure != null)
            throw new Exception($"TimeStamp request to the \"{tsaServerURI}\" failed.");
        TimeStampToken token = response.TimeStampToken;

        //Throw an exception if the responce doesn't contain the timestamp:
        if (token == null)
            throw new Exception($"TimeStamp request to the \"{tsaServerURI}\" failed.");
        return token.GetEncoded();
    }
}
