using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Ionic.Zlib;
using TLSharp.Core.MTProto;
using TLSharp.Core.MTProto.Crypto;
using TLSharp.Core.Requests;
using TLSharp.Core.Utils;

namespace TLSharp.Core.Network
{
    public class MtProtoSender
    {
        //private ulong sessionId = GenerateRandomUlong();

        private TcpTransport _transport;
        private Session _session;

        public List<ulong> needConfirmation = new List<ulong>();

        private readonly Dictionary<long, Tuple<TeleSharp.TL.TLMethod, TaskCompletionSource<bool>>> runningRequests = new Dictionary<long, Tuple<TeleSharp.TL.TLMethod, TaskCompletionSource<bool>>>();

        private TaskCompletionSource<bool> finishedListening;
        public Task finishedListeningTask => finishedListening.Task;

        public event EventHandler<TeleSharp.TL.TLAbsUpdates> UpdateMessage;


        private long connectMessageID;


        public MtProtoSender(TcpTransport transport, Session session)
        {
            _transport = transport;
            _session = session;

            StartListening();

        }

        private async void StartListening()
        {
            Debug.WriteLine("Start listening");
            finishedListening = new TaskCompletionSource<bool>();
            try
            {


                while (true)
                {

                    var message = await _transport.Receieve().ConfigureAwait(false);
                    if (message == null)
                        break;

                    var decodedMessage = DecodeMessage(message.Body);

                    using (var messageStream = new MemoryStream(decodedMessage.Item1, false))
                    using (var messageReader = new BinaryReader(messageStream))
                    {
                        processMessage(decodedMessage.Item2, decodedMessage.Item3, messageReader);
                    }
                }
                finishedListening.SetResult(true);
            }
            catch(ObjectDisposedException ex)
            {
                //disposed
            }
        }

        public void ChangeTransport(TcpTransport transport)
        {
            _transport = transport;
        }

        private int GenerateSequence(bool confirmed)
        {
            return confirmed ? _session.Sequence++ * 2 + 1 : _session.Sequence * 2;
        }

        public async Task Send(TeleSharp.TL.TLMethod request)
        {
            // TODO: refactor
            if (needConfirmation.Any())
            {
                var ackRequest = new AckRequest(needConfirmation);
                using (var memory = new MemoryStream())
                using (var writer = new BinaryWriter(memory))
                {
                    ackRequest.SerializeBody(writer);
                    await Send(memory.ToArray(), ackRequest);
                    needConfirmation.Clear();
                }
            }


            //using (var memory = new MemoryStream())
            //using (var writer = new BinaryWriter(memory))
            //{
            //    request.SerializeBody(writer);
            //    await Send(memory.ToArray(), request);
            //}



            TaskCompletionSource<bool> responseSource;
            using (var memory = new MemoryStream())
            using (var writer = new BinaryWriter(memory))
            {
                //var messageId = _session.GetNewMessageId();
                //request.MessageId = messageId;

                //if (request.GetType() == typeof(TeleSharp.TL.TLRequestInvokeWithLayer))
                //{
                //    connectMessageID = messageId;
                //}


                request.SerializeBody(writer);
                request.MessageId = _session.GetNewMessageId();

                Debug.WriteLine($"Send request - {request.MessageId}");
                responseSource = new TaskCompletionSource<bool>();
                runningRequests.Add(request.MessageId, Tuple.Create(request, responseSource));

                await Send(memory.ToArray(), request);
                Debug.WriteLine("sended");
            }

            await responseSource.Task;
            Debug.WriteLine("complete");
            if (runningRequests.ContainsKey(request.MessageId))
                runningRequests.Remove(request.MessageId);
            Debug.WriteLine("request removed from queue");

            _session.Save();
            Debug.WriteLine("session saved");

        }

        public async Task Send(byte[] packet, TeleSharp.TL.TLMethod request)
        {

            byte[] msgKey;
            byte[] ciphertext;
            using (MemoryStream plaintextPacket = makeMemory(8 + 8 + 8 + 4 + 4 + packet.Length))
            {
                using (BinaryWriter plaintextWriter = new BinaryWriter(plaintextPacket))
                {
                    plaintextWriter.Write(_session.Salt);
                    plaintextWriter.Write(_session.Id);
                    plaintextWriter.Write(request.MessageId);
                    plaintextWriter.Write(GenerateSequence(request.Confirmed));
                    plaintextWriter.Write(packet.Length);
                    plaintextWriter.Write(packet);

                    msgKey = Helpers.CalcMsgKey(plaintextPacket.GetBuffer());
                    ciphertext = AES.EncryptAES(Helpers.CalcKey(_session.AuthKey.Data, msgKey, true), plaintextPacket.GetBuffer());
                }
            }

            using (MemoryStream ciphertextPacket = makeMemory(8 + 16 + ciphertext.Length))
            {
                using (BinaryWriter writer = new BinaryWriter(ciphertextPacket))
                {
                    writer.Write(_session.AuthKey.Id);
                    writer.Write(msgKey);
                    writer.Write(ciphertext);

                    await _transport.Send(ciphertextPacket.GetBuffer());
                }
            }
        }

        private Tuple<byte[], ulong, int> DecodeMessage(byte[] body)
        {
            byte[] message;
            ulong remoteMessageId;
            int remoteSequence;

            using (var inputStream = new MemoryStream(body))
            using (var inputReader = new BinaryReader(inputStream))
            {
                if (inputReader.BaseStream.Length < 8)
                    throw new InvalidOperationException($"Can't decode packet");

                ulong remoteAuthKeyId = inputReader.ReadUInt64(); // TODO: check auth key id
                byte[] msgKey = inputReader.ReadBytes(16); // TODO: check msg_key correctness
                AESKeyData keyData = Helpers.CalcKey(_session.AuthKey.Data, msgKey, false);

                byte[] plaintext = AES.DecryptAES(keyData, inputReader.ReadBytes((int)(inputStream.Length - inputStream.Position)));

                using (MemoryStream plaintextStream = new MemoryStream(plaintext))
                using (BinaryReader plaintextReader = new BinaryReader(plaintextStream))
                {
                    var remoteSalt = plaintextReader.ReadUInt64();
                    var remoteSessionId = plaintextReader.ReadUInt64();
                    remoteMessageId = plaintextReader.ReadUInt64();
                    remoteSequence = plaintextReader.ReadInt32();
                    int msgLen = plaintextReader.ReadInt32();
                    message = plaintextReader.ReadBytes(msgLen);
                }
            }
            return new Tuple<byte[], ulong, int>(message, remoteMessageId, remoteSequence);
        }

        //public async Task<byte[]> Receive(TeleSharp.TL.TLMethod request)
        //{
        //    while (!request.ConfirmReceived)
        //    {
        //        var result = DecodeMessage((await _transport.Receieve()).Body);

        //        using (var messageStream = new MemoryStream(result.Item1, false))
        //        using (var messageReader = new BinaryReader(messageStream))
        //        {
        //            processMessage(result.Item2, result.Item3, messageReader, request);
        //        }
        //    }

        //    return null;
        //}

        //public async Task SendPingAsync()
        //{
        //    var pingRequest = new PingRequest();
        //    using (var memory = new MemoryStream())
        //    using (var writer = new BinaryWriter(memory))
        //    {
        //        pingRequest.SerializeBody(writer);
        //        await Send(memory.ToArray(), pingRequest);
        //    }

        //    await Receive(pingRequest);
        //}

        private void processMessage(ulong messageId, int sequence, BinaryReader messageReader)
        {
            // TODO: check salt
            // TODO: check sessionid
            // TODO: check seqno

            //logger.debug("processMessage: msg_id {0}, sequence {1}, data {2}", BitConverter.ToString(((MemoryStream)messageReader.BaseStream).GetBuffer(), (int) messageReader.BaseStream.Position, (int) (messageReader.BaseStream.Length - messageReader.BaseStream.Position)).Replace("-","").ToLower());
            Debug.WriteLine("new ProccesMessage");
            needConfirmation.Add(messageId);
            uint code = messageReader.ReadUInt32();
            messageReader.BaseStream.Position -= 4;
            switch (code)
            {
                case 0x73f1f8dc: // container
                                 //logger.debug("MSG container");
                    Debug.WriteLine("HandleContainer");

                    HandleContainer(messageId, sequence, messageReader);
                    return;
                case 0x7abe77ec: // ping
                                 //logger.debug("MSG ping");
                    Debug.WriteLine("HandlePing");

                    HandlePing(messageId, sequence, messageReader);
                    return;
                case 0x347773c5: // pong
                                 //logger.debug("MSG pong");
                    Debug.WriteLine("HandlePong");

                    HandlePong(messageId, sequence, messageReader);
                    return;

                case 0xae500895: // future_salts
                                 //logger.debug("MSG future_salts");
                    Debug.WriteLine("HandleFutureSalts");

                    //HandleFutureSalts(messageId, sequence, messageReader);
                    return;
                case 0x9ec20908: // new_session_created
                                 //logger.debug("MSG new_session_created");
                    Debug.WriteLine("HandleNewSessionCreated");

                    HandleNewSessionCreated(messageId, sequence, messageReader);
                    return;

                case 0x62d6b459: // msgs_ack
                                 //logger.debug("MSG msds_ack");
                    Debug.WriteLine("HandleMsgsAck");

                    HandleMsgsAck(messageId, sequence, messageReader);
                    return;

                case 0xedab447b: // bad_server_salt
                                 //logger.debug("MSG bad_server_salt");
                    Debug.WriteLine("HandleBadServerSalt");

                    HandleBadServerSalt(messageId, sequence, messageReader);
                    return;

                case 0xa7eff811: // bad_msg_notification
                                 //logger.debug("MSG bad_msg_notification");
                    Debug.WriteLine("HandleBadMsgNotification");

                    HandleBadMsgNotification(messageId, sequence, messageReader);
                    return;

                case 0x276d3ec6: // msg_detailed_info
                                 //logger.debug("MSG msg_detailed_info");
                    Debug.WriteLine("HandleMsgDetailedInfo");

                    HandleMsgDetailedInfo(messageId, sequence, messageReader);
                    return;

                case 0xf35c6d01: // rpc_result
                                 //logger.debug("MSG rpc_result");
                    Debug.WriteLine("HandleRpcResult");

                    HandleRpcResult(messageId, sequence, messageReader);
                    return;

                case 0x3072cfa1: // gzip_packed
                                 //logger.debug("MSG gzip_packed");
                    Debug.WriteLine("HandleGzipPacked");

                    HandleGzipPacked(messageId, sequence, messageReader);
                    return;

                case 0xe317af7e: //updatesTooLong
                                 // case 0xd3f45784: old
                case 0x16812688: //updateShortChatMessage                   
                                 // case 0x2b2fbd4e: old
                case 0x914fbf11: //updateShortMessage
                case 0x78d4dec1: //updateShort
                case 0x725b04c3: //updatesCombined
                case 0x74ae4240: //updates
                case 0x11f1331c: //updateShortSentMessage
                    Debug.WriteLine("HandleUpdate");

                    HandleUpdate(messageId, sequence, messageReader);
                    return;

                default:
                    Debug.WriteLine($"Unknown messageCode: {code}");
                    //logger.debug("unknown message: {0}", code);
                    return;
            }
        }

        private bool HandleUpdate(ulong messageId, int sequence, BinaryReader messageReader)
        {
            try
            {
                var updates = (TeleSharp.TL.TLAbsUpdates)TeleSharp.TL.ObjectUtils.DeserializeObject(messageReader);
                OnUpdateMessage(updates);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: " + e.Message);
                return false;
            }

        }

        private void OnUpdateMessage(TeleSharp.TL.TLAbsUpdates updates)
        {
            UpdateMessage?.Invoke(this, updates);
        }

        private void HandleGzipPacked(ulong messageId, int sequence, BinaryReader messageReader)
        {
            uint code = messageReader.ReadUInt32();
            byte[] packedData = GZipStream.UncompressBuffer(Serializers.Bytes.read(messageReader));
            using (MemoryStream packedStream = new MemoryStream(packedData, false))
            using (BinaryReader compressedReader = new BinaryReader(packedStream))
            {
                processMessage(messageId, sequence, compressedReader);
            }
        }

        private void HandleRpcResult(ulong messageId, int sequence, BinaryReader messageReader)
        {
            uint code = messageReader.ReadUInt32();
            ulong requestId = messageReader.ReadUInt64();

            long convertedReqID = Convert.ToInt64(requestId);
            Debug.WriteLine($"HandleRpcResult: requestId - {requestId},converted - {convertedReqID}, messageId - {messageId}");


            if (!runningRequests.ContainsKey(convertedReqID))
            {
                Debug.WriteLine("request don't find");
                return;
            }

            var requestInfo = runningRequests[convertedReqID];
            var request = requestInfo.Item1;

            request.ConfirmReceived = true;
            Debug.WriteLine("try parse rpcResult");

            uint innerCode = messageReader.ReadUInt32();
            if (innerCode == 0x2144ca19)
            { // rpc_error
                Debug.WriteLine("rpc error");
                int errorCode = messageReader.ReadInt32();
                string errorMessage = Serializers.String.read(messageReader);
                request.OnError(errorCode, errorMessage);
                requestInfo.Item2.SetResult(true);
            }
            else if (innerCode == 0x3072cfa1)
            {
                try
                {
                    Debug.WriteLine("gzip");
                    // gzip_packed
                    byte[] packedData = Serializers.Bytes.read(messageReader);
                    using (var ms = new MemoryStream())
                    {
                        using (var packedStream = new MemoryStream(packedData, false))
                        using (var zipStream = new GZipStream(packedStream, CompressionMode.Decompress))
                        {
                            zipStream.CopyTo(ms);
                            ms.Position = 0;
                        }
                        using (var compressedReader = new BinaryReader(ms))
                        {
                            request.deserializeResponse(compressedReader);
                            requestInfo.Item2.SetResult(true);

                        }
                    }
                }
                catch (ZlibException ex)
                {

                }
            }
            else
            {
                Debug.WriteLine("some else");
                messageReader.BaseStream.Position -= 4;
                request.deserializeResponse(messageReader);
                requestInfo.Item2.SetResult(true);

            }

        }

        private bool HandleMsgDetailedInfo(ulong messageId, int sequence, BinaryReader messageReader)
        {
            return false;
        }

        private void HandleBadMsgNotification(ulong messageId, int sequence, BinaryReader messageReader)
        {
            uint code = messageReader.ReadUInt32();
            ulong requestId = messageReader.ReadUInt64();
            int requestSequence = messageReader.ReadInt32();
            int errorCode = messageReader.ReadInt32();

            var reqIdLong = Convert.ToInt64(requestId);
            if (runningRequests.ContainsKey(reqIdLong))
            {
                runningRequests[reqIdLong].Item1.OnError(errorCode, null);
                runningRequests[reqIdLong].Item2.SetResult(true);
            }

        }

        private void HandleBadServerSalt(ulong messageId, int sequence, BinaryReader messageReader)
        {
            Debug.WriteLine("messageId: " + messageId);
            uint code = messageReader.ReadUInt32();
            long badMsgId = messageReader.ReadInt64();

            int badMsgSeqNo = messageReader.ReadInt32();
            int errorCode = messageReader.ReadInt32();
            ulong newSalt = messageReader.ReadUInt64();

            Debug.WriteLine("bad_server_salt: msgid {0}, seq {1}, errorcode {2}, newsalt {3}, oldsalt {4}", badMsgId, badMsgSeqNo, errorCode, newSalt, _session.Salt);

            _session.Salt = newSalt;

            //if (runningRequests.ContainsKey(connectMessageID))
            //{
            //    runningRequests[connectMessageID].Item2.SetResult(true);
            //    Send(runningRequests[connectMessageID].Item1);
            //}

            if (runningRequests.ContainsKey(Convert.ToInt64(messageId)))
            {
                Debug.WriteLine("contains messageid");
            }
            if (!runningRequests.ContainsKey(badMsgId))
                return;
            Debug.WriteLine("contains badmessageid");

            //resend


            runningRequests[badMsgId].Item1.OnError(errorCode, null);
            runningRequests[badMsgId].Item2.SetResult(true);


            /*
            if(!runningRequests.ContainsKey(badMsgId)) {
                logger.debug("bad server salt on unknown message");
                return true;
            }
            */


            //MTProtoRequest request = runningRequests[badMsgId];
            //request.OnException(new MTProtoBadServerSaltException(salt));

            //return true;
        }

        private void HandleMsgsAck(ulong messageId, int sequence, BinaryReader messageReader)
        {
            //return false;
        }

        private void HandleNewSessionCreated(ulong messageId, int sequence, BinaryReader messageReader)
        {
            var firstMsgId = messageReader.ReadUInt64();
            var uniqueId = messageReader.ReadUInt64();
            var serverSalt = messageReader.ReadUInt64();

            _session.Salt = serverSalt;
            _session.Id = uniqueId;
            //return false;
        }

        private void HandleFutureSalts(ulong messageId, int sequence, BinaryReader messageReader)
        {
            uint code = messageReader.ReadUInt32();
            ulong requestId = messageReader.ReadUInt64();

            messageReader.BaseStream.Position -= 12;

            throw new NotImplementedException("Handle future server salts function isn't implemented.");
            /*
			if (!runningRequests.ContainsKey(requestId))
			{
				logger.info("future salts on unknown request");
				return false;
			}
			*/

            //	MTProtoRequest request = runningRequests[requestId];
            //	runningRequests.Remove(requestId);
            //	request.OnResponse(messageReader);

            //return true;
        }

        private void HandlePong(ulong messageId, int sequence, BinaryReader messageReader)
        {
            uint code = messageReader.ReadUInt32();
            ulong msgId = messageReader.ReadUInt64();
            var convMsgId = Convert.ToInt64(msgId);
            if (!runningRequests.ContainsKey(convMsgId))
            {
                Debug.WriteLine("Don't find converted messageId with Ping");
                return;
            }
            runningRequests[convMsgId].Item1.ConfirmReceived = true;
            runningRequests[convMsgId].Item2.SetResult(true);
        }

        private bool HandlePing(ulong messageId, int sequence, BinaryReader messageReader)
        {
            return false;
        }

        private void HandleContainer(ulong messageId, int sequence, BinaryReader messageReader)
        {
            uint code = messageReader.ReadUInt32();
            int size = messageReader.ReadInt32();
            Debug.WriteLine("size - " + size);
            for (int i = 0; i < size; i++)
            {
                ulong innerMessageId = messageReader.ReadUInt64(); // TODO: Remove this reading and call ProcessMessage directly(remove appropriate params in ProcMsg)
                Debug.WriteLine($"Container innerMessageId: {innerMessageId}");
                messageReader.ReadInt32(); // innerSequence
                int innerLength = messageReader.ReadInt32();
                long beginPosition = messageReader.BaseStream.Position;

                try
                {
                    processMessage(innerMessageId, sequence, messageReader);

                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Exception: {ex.Message}");
                }
                messageReader.BaseStream.Position = beginPosition + innerLength; // shift to next message
            }

            return;
        }

        private MemoryStream makeMemory(int len)
        {
            return new MemoryStream(new byte[len], 0, len, true, true);
        }
    }

    public class FloodException : Exception
    {
        public TimeSpan TimeToWait { get; private set; }

        internal FloodException(TimeSpan timeToWait)
            : base($"Flood prevention. Telegram now requires your program to do requests again only after {timeToWait.TotalSeconds} seconds have passed ({nameof(TimeToWait)} property)." +
                    " If you think the culprit of this problem may lie in TLSharp's implementation, open a Github issue please.")
        {
            TimeToWait = timeToWait;
        }
    }

    internal abstract class DataCenterMigrationException : Exception
    {
        internal int DC { get; private set; }

        private const string REPORT_MESSAGE =
            " See: https://github.com/sochix/TLSharp#i-get-a-xxxmigrationexception-or-a-migrate_x-error";

        protected DataCenterMigrationException(string msg, int dc) : base(msg + REPORT_MESSAGE)
        {
            DC = dc;
        }
    }

    internal class PhoneMigrationException : DataCenterMigrationException
    {
        internal PhoneMigrationException(int dc)
            : base($"Phone number registered to a different DC: {dc}.", dc)
        {
        }
    }

    internal class FileMigrationException : DataCenterMigrationException
    {
        internal FileMigrationException(int dc)
            : base($"File located on a different DC: {dc}.", dc)
        {
        }
    }

    internal class UserMigrationException : DataCenterMigrationException
    {
        internal UserMigrationException(int dc)
            : base($"User located on a different DC: {dc}.", dc)
        {
        }
    }
}