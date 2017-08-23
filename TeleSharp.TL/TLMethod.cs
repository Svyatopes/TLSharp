using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TeleSharp.TL;
namespace TeleSharp.TL
{
    public abstract class TLMethod : TLObject
    {
        public RpcRequestError Error { get; private set; }
        public string ErrorMessage { get; private set; }

        public virtual void OnError(int errorCode, string errorMessage)
        {
            Error = (RpcRequestError)errorCode;
            ErrorMessage = errorMessage;
        }

        public abstract void deserializeResponse(BinaryReader stream);
        #region MTPROTO
        public long MessageId { get; set; }
        public int Sequence { get; set; }
        public bool Dirty { get; set; }
        public bool Sended { get; private set; }
        public DateTime SendTime { get; private set; }
        public bool ConfirmReceived { get; set; }
        public virtual bool Confirmed { get; } = true;
        public virtual bool Responded { get; } = false;

        public virtual void OnSendSuccess()
        {
            SendTime = DateTime.Now;
            Sended = true;
        }

        public virtual void OnConfirm()
        {
            ConfirmReceived = true;
        }

        public bool NeedResend
        {
            get
            {
                return Dirty || (Confirmed && !ConfirmReceived && DateTime.Now - SendTime > TimeSpan.FromSeconds(3));
            }
        }


        public void ResetError()
        {
            Error = RpcRequestError.None;
            ErrorMessage = null;
        }

        public void ThrowIfHasError()
        {
            if (Error != RpcRequestError.None)
            {
                throw new TelegramReqestException(Error, ErrorMessage);
            }
        }
        #endregion

    }

    
}
