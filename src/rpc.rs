//! Remote Procedure Calls

// TODO: docs for everything
#![allow(missing_docs)]

use prost::Message;
use std::convert::TryFrom;
use std::io::{self, Error, ErrorKind, Read};
use tendermint::proposal::{SignProposalRequest, SignedProposalResponse};
use tendermint::public_key::{PubKeyRequest, PublicKey};
use tendermint::vote::{SignVoteRequest, SignedVoteResponse};
use tendermint_proto::{
    privval::{message::Sum, Message as PrivMessage, PingRequest, PingResponse, RemoteSignerError},
    types::SignedMsgType,
};

/// Maximum size of an RPC message
pub const MAX_MSG_LEN: usize = 1024;

/// Requests to the KMS
#[derive(Debug)]
pub enum Request {
    /// Sign the given message
    SignProposal(SignProposalRequest),
    SignVote(SignVoteRequest),
    ShowPublicKey(PubKeyRequest),

    // PingRequest is a PrivValidatorSocket message to keep the connection alive.
    ReplyPing(PingRequest),
}

/// Responses from the KMS
pub enum Response {
    /// Signature response
    SignedVote(SignedVoteResponse),
    SignedProposal(SignedProposalResponse),
    Ping(PingResponse),
    PublicKey(PublicKey),
}

impl Response {
    pub fn encode_msg_wrapped(self) -> Result<Vec<u8>, Error> {
        let mut buf = vec![];
        match self {
            Response::SignedProposal(sp) => {
                let msg = PrivMessage {
                    sum: Some(Sum::SignedProposalResponse(sp.into())),
                };
                msg.encode(&mut buf)
            }
            Response::SignedVote(sv) => {
                let msg = PrivMessage {
                    sum: Some(Sum::SignedVoteResponse(sv.into())),
                };
                msg.encode(&mut buf)
            }
            Response::Ping(ping) => {
                let msg = PrivMessage {
                    sum: Some(Sum::PingResponse(ping)),
                };
                msg.encode(&mut buf)
            }
            Response::PublicKey(pk) => {
                let msg = PrivMessage {
                    sum: Some(Sum::PubKeyResponse(pk.into())),
                };
                msg.encode(&mut buf)
            }
        }
        .map_err(|error| Error::new(ErrorKind::Other, error))?;
        Ok(buf)
    }
}

pub trait TendermintRequest {
    fn consensus_state(&self) -> (SignedMsgType, tendermint::consensus::State);
    fn height(&self) -> tendermint::block::Height;
    fn to_sign_bytes(&self) -> Vec<u8>;
    fn build_response(self, error: Option<RemoteSignerError>) -> Response;
    fn set_signature(&mut self, signature: ed25519_dalek::Signature);
}

impl Request {
    /// Read a request from the given readable
    pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
        // this buffer contains the overall length and the amino prefix (for the registered types)
        let mut buf = vec![0; MAX_MSG_LEN];
        let bytes_read = r.read(&mut buf)?;
        if bytes_read < 4 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Did not read enough bytes to continue.",
            ));
        }
        let req = PrivMessage::decode(&buf[0..bytes_read])?;
        let err = Error::new(ErrorKind::InvalidData, "Invalid request.");
        match req.sum {
            Some(Sum::PubKeyRequest(pkr)) => {
                let pkr = PubKeyRequest::try_from(pkr).map_err(|_| err)?;
                Ok(Request::ShowPublicKey(pkr))
            }
            Some(Sum::PingRequest(pr)) => Ok(Request::ReplyPing(pr)),
            Some(Sum::SignVoteRequest(svr)) => {
                let svr = SignVoteRequest::try_from(svr).map_err(|_| err)?;
                Ok(Request::SignVote(svr))
            }
            Some(Sum::SignProposalRequest(spr)) => {
                let spr = SignProposalRequest::try_from(spr).map_err(|_| err)?;
                Ok(Request::SignProposal(spr))
            }
            _ => Err(err),
        }
    }
}

impl TendermintRequest for SignVoteRequest {
    fn consensus_state(&self) -> (SignedMsgType, tendermint::consensus::State) {
        let mut state = self.vote.consensus_state();
        let smtype = if self.vote.is_precommit() {
            state.step = 2;
            SignedMsgType::Precommit
        } else {
            state.step = 1;
            SignedMsgType::Prevote
        };
        (smtype, state)
    }

    fn height(&self) -> tendermint::block::Height {
        self.vote.height
    }

    fn set_signature(&mut self, signature: ed25519_dalek::Signature) {
        self.vote.signature = tendermint::Signature::Ed25519(signature);
    }

    fn to_sign_bytes(&self) -> Vec<u8> {
        self.to_signable_vec().expect("todo")
    }

    fn build_response(self, error: Option<RemoteSignerError>) -> Response {
        let response = if let Some(e) = error {
            SignedVoteResponse {
                vote: None,
                error: Some(e),
            }
        } else {
            SignedVoteResponse {
                vote: Some(self.vote),
                error: None,
            }
        };

        Response::SignedVote(response)
    }
}

impl TendermintRequest for SignProposalRequest {
    fn consensus_state(&self) -> (SignedMsgType, tendermint::consensus::State) {
        let mut state = self.proposal.consensus_state();
        state.step = 0;
        (SignedMsgType::Proposal, state)
    }

    fn height(&self) -> tendermint::block::Height {
        self.proposal.height
    }

    fn set_signature(&mut self, signature: ed25519_dalek::Signature) {
        self.proposal.signature = tendermint::Signature::Ed25519(signature);
    }

    fn to_sign_bytes(&self) -> Vec<u8> {
        self.to_signable_vec().expect("todo")
    }

    fn build_response(self, error: Option<RemoteSignerError>) -> Response {
        let response = if let Some(e) = error {
            SignedProposalResponse {
                proposal: None,
                error: Some(e),
            }
        } else {
            SignedProposalResponse {
                proposal: Some(self.proposal),
                error: None,
            }
        };

        Response::SignedProposal(response)
    }
}
