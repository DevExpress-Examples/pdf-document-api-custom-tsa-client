using DevExpress.Pdf;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Diagnostics;

namespace CustomTsaClient
{
    public class BouncyCastleTsaClient : ITsaClient
    {
        readonly Uri tsaServerURI;

        readonly IDigest hashCalculator;

        public BouncyCastleTsaClient(Uri tsaServerURI, IDigest hashCalculator)
        {
            this.tsaServerURI = tsaServerURI;
            this.hashCalculator = hashCalculator;
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
            HttpWebRequest httpRequest = (HttpWebRequest)WebRequest.Create(tsaServerURI);
            httpRequest.Method = "POST";
            httpRequest.ContentType = "application/timestamp-query";
            httpRequest.ContentLength = requestBytes.Length;
            using (Stream requestStream = httpRequest.GetRequestStream())
                requestStream.Write(requestBytes, 0, requestBytes.Length);
            
            //Get a responce from the server:
            HttpWebResponse httpResponce = (HttpWebResponse)httpRequest.GetResponse();
            using (Stream respStream = new BufferedStream(httpResponce.GetResponseStream()))
            {
                //Read the responce:
                TimeStampResponse response = new TimeStampResponse(respStream);
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
    }

}
