using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TeleSharp.TL;
namespace TeleSharp.TL
{
    public class TLObjectAttribute : Attribute
    {
        public int Constructor { get; private set; }
        
        public TLObjectAttribute(int Constructor)
        {
            this.Constructor = Constructor;
        }
    }

   

    public abstract class TLObject
    {
        public abstract int Constructor { get; }
        public abstract void SerializeBody(BinaryWriter bw);
        public abstract void DeserializeBody(BinaryReader br);
        public byte[] Serialize()
        {
            using (MemoryStream m = new MemoryStream())
            using (BinaryWriter bw = new BinaryWriter(m))
            {
                Serialize(bw);
                bw.Close();
                m.Close();
                return m.GetBuffer();
            }
        }
        public void Serialize(BinaryWriter writer)
        {
            writer.Write(Constructor);
            SerializeBody(writer);
        }
        public void Deserialize(BinaryReader reader)
        {
            int constructorId = reader.ReadInt32();
            if (constructorId != Constructor)
                throw new InvalidDataException("Constructor Invalid");
            DeserializeBody(reader);
        }

       
    }

    public class TelegramReqestException : Exception
    {
        public readonly RpcRequestError error;
        public readonly string errorMessage;

        public TelegramReqestException(RpcRequestError error, string errorMessage) : base($"{error} - {errorMessage}")
        {
            this.error = error;
            this.errorMessage = errorMessage;
        }
    }

    public enum RpcRequestError
    {
        None = 0,

        // Message level errors

        MessageIdTooLow = 16,           // msg_id too low (most likely, client time is wrong; it would be worthwhile to synchronize it using msg_id notifications and re-send the original message with the correct msg_id or wrap it in a container with a new msg_id if the original message had waited too long on the client to be transmitted)
        MessageIdTooHigh,               // msg_id too high (similar to the previous case, the client time has to be synchronized, and the message re-sent with the correct msg_id)
        CorruptedMessageId,             // incorrect two lower order msg_id bits (the server expects client message msg_id to be divisible by 4)
        DuplicateOfMessageContainerId,  // container msg_id is the same as msg_id of a previously received message (this must never happen)
        MessageTooOld,                  // message too old, and it cannot be verified whether the server has received a message with this msg_id or not

        MessageSeqNoTooLow = 32,        // msg_seqno too low (the server has already received a message with a lower msg_id but with either a higher or an equal and odd seqno)
        MessageSeqNoTooHigh,            // msg_seqno too high (similarly, there is a message with a higher msg_id but with either a lower or an equal and odd seqno)
        EvenSeqNoExpected,              // an even msg_seqno expected (irrelevant message), but odd received
        OddSeqNoExpected,               // odd msg_seqno expected (relevant message), but even received

        IncorrectServerSalt = 48,       // incorrect server salt (in this case, the bad_server_salt response is received with the correct salt, and the message is to be re-sent with it)
        InvalidContainer = 64,           // invalid container

        // Api-request level errors

        MigrateDataCenter = 303,
        BadRequest = 400,
        Unauthorized = 401,
        Forbidden = 403,
        NotFound = 404,
        Flood = 420,
        InternalServer = 500
    }
}
