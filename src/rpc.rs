//! Remote Procedure Calls

// TODO: docs for everything
#![allow(missing_docs)]

use prost::{decode_length_delimiter, Message};
use std::convert::{TryFrom, TryInto};
use std::io::{self, Error, ErrorKind, Read};
use tendermint::proposal::{SignProposalRequest, SignedProposalResponse};
use tendermint::public_key::{PubKeyRequest, PublicKey};
use tendermint::vote::{SignVoteRequest, SignedVoteResponse};
use tendermint_proto::{
    privval::{
        message::Sum, Message as PrivMessage, PingRequest, PingResponse, RemoteSignerError,
        SignProposalRequest as RawSignProposalRequest, SignVoteRequest as RawSignVoteRequest,
    },
    types::{
        CanonicalBlockId, CanonicalPartSetHeader, CanonicalProposal, CanonicalVote, SignedMsgType,
    },
};

/// Maximum size of an RPC message
pub const MAX_MSG_LEN: usize = 1024;

/// Requests to the KMS
#[derive(Debug)]
pub enum Request {
    /// Sign the given message
    SignProposal(RawSignProposalRequest),
    SignVote(RawSignVoteRequest),
    ShowPublicKey(PubKeyRequest),

    // PingRequest is a PrivValidatorSocket message to keep the connection alive.
    ReplyPing(PingRequest),
}

/// Responses from the KMS
#[derive(Debug)]
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
                msg.encode_length_delimited(&mut buf)
            }
            Response::SignedVote(sv) => {
                let msg = PrivMessage {
                    sum: Some(Sum::SignedVoteResponse(sv.into())),
                };
                msg.encode_length_delimited(&mut buf)
            }
            Response::Ping(ping) => {
                let msg = PrivMessage {
                    sum: Some(Sum::PingResponse(ping)),
                };
                msg.encode_length_delimited(&mut buf)
            }
            Response::PublicKey(pk) => {
                let msg = PrivMessage {
                    sum: Some(Sum::PubKeyResponse(pk.into())),
                };
                msg.encode_length_delimited(&mut buf)
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
        let mut buf = vec![0; MAX_MSG_LEN];
        let bytes_read = r.read(&mut buf)?;

        // FIXME: PrivMessage::decode_length_delimited was returning "unexpected VarInt"
        let len = decode_length_delimiter(buf[..bytes_read].as_ref())?;
        let start = bytes_read - len;

        let req = PrivMessage::decode(&buf[start..bytes_read])?; //PrivMessage::decode_length_delimited(&buf[0..bytes_read])?;
        let err = Error::new(ErrorKind::InvalidData, "Invalid request.");
        match req.sum {
            Some(Sum::PubKeyRequest(pkr)) => {
                let pkr = PubKeyRequest::try_from(pkr).map_err(|e| err)?;
                Ok(Request::ShowPublicKey(pkr))
            }
            Some(Sum::PingRequest(pr)) => Ok(Request::ReplyPing(pr)),
            Some(Sum::SignVoteRequest(svr)) => {
                // let svr = SignVoteRequest::try_from(svr).map_err(|e| {
                //     err
                // })?;
                Ok(Request::SignVote(svr))
            }
            Some(Sum::SignProposalRequest(spr)) => {
                // let spr = SignProposalRequest::try_from(spr).map_err(|e| {
                //     err
                // })?;
                Ok(Request::SignProposal(spr))
            }
            x => {
                dbg!(x);
                Err(err)
            }
        }
    }
}

impl TendermintRequest for RawSignVoteRequest {
    fn consensus_state(&self) -> (SignedMsgType, tendermint::consensus::State) {
        // let mut state = self.vote.consensus_state();
        // let smtype = if self.vote.is_precommit() {
        //     state.step = 2;
        //     SignedMsgType::Precommit
        // } else {
        //     state.step = 1;
        //     SignedMsgType::Prevote
        // };
        // (smtype, state)

        let vote = self.vote.as_ref().expect("fixme");
        let vtype = vote.r#type();
        (
            vtype,
            tendermint::consensus::State {
                height: tendermint::block::Height::try_from(vote.height).expect("fixme"),
                round: tendermint::block::Round::try_from(vote.round).expect("fixme"),
                step: match vtype {
                    SignedMsgType::Precommit => 2,
                    SignedMsgType::Prevote => 1,
                    _ => unreachable!("unknown vote"),
                },
                block_id: vote
                    .block_id
                    .as_ref()
                    .map(|x| tendermint::block::Id::try_from(x.clone()).expect("fixme")),
            },
        )
    }

    fn height(&self) -> tendermint::block::Height {
        // self.vote.height
        self.vote
            .as_ref()
            .expect("fixme")
            .height
            .try_into()
            .expect("fixme")
    }

    fn set_signature(&mut self, signature: ed25519_dalek::Signature) {
        let mut vote = self.vote.as_mut().expect("fixme");

        vote.signature = signature.to_bytes().to_vec(); //tendermint::Signature::Ed25519(signature);
    }

    fn to_sign_bytes(&self) -> Vec<u8> {
        //self.to_signable_vec().expect("todo")

        let mut r = vec![];
        let vote = self.vote.as_ref().expect("fixme");
        CanonicalVote {
            r#type: vote.r#type,
            height: vote.height,
            round: vote.round as i64,
            block_id: vote.block_id.as_ref().map(|x| CanonicalBlockId {
                hash: x.hash.clone(),
                part_set_header: x.part_set_header.as_ref().map(|y| CanonicalPartSetHeader {
                    total: y.total,
                    hash: y.hash.clone(),
                }),
            }),
            timestamp: vote.timestamp.clone(),
            chain_id: self.chain_id.clone(),
        }
        .encode_length_delimited(&mut r)
        .expect("todo");
        r
    }

    fn build_response(self, error: Option<RemoteSignerError>) -> Response {
        let response = if let Some(e) = error {
            SignedVoteResponse {
                vote: None,
                error: Some(e),
            }
        } else {
            SignedVoteResponse {
                vote: Some(SignVoteRequest::try_from(self).expect("fixme").vote),
                error: None,
            }
        };

        Response::SignedVote(response)
    }
}

impl TendermintRequest for RawSignProposalRequest {
    fn consensus_state(&self) -> (SignedMsgType, tendermint::consensus::State) {
        // let mut state = self.proposal.consensus_state();
        // state.step = 0;
        let proposal = self.proposal.as_ref().expect("fixme");
        (
            SignedMsgType::Proposal,
            tendermint::consensus::State {
                height: tendermint::block::Height::try_from(proposal.height).expect("fixme"),
                round: tendermint::block::Round::try_from(proposal.round).expect("fixme"),
                step: 0,
                block_id: proposal
                    .block_id
                    .as_ref()
                    .map(|x| tendermint::block::Id::try_from(x.clone()).expect("fixme")),
            },
        )
    }

    fn height(&self) -> tendermint::block::Height {
        self.proposal
            .as_ref()
            .expect("fixme")
            .height
            .try_into()
            .expect("fixme")
    }

    fn set_signature(&mut self, signature: ed25519_dalek::Signature) {
        let mut proposal = self.proposal.as_mut().expect("fixme");

        proposal.signature = signature.to_bytes().to_vec(); //tendermint::Signature::Ed25519(signature);
    }

    fn to_sign_bytes(&self) -> Vec<u8> {
        let mut r = vec![];
        let proposal = self.proposal.as_ref().expect("fixme");
        CanonicalProposal {
            r#type: proposal.r#type,
            height: proposal.height,
            round: proposal.round as i64,
            pol_round: proposal.pol_round as i64,
            block_id: proposal.block_id.as_ref().map(|x| CanonicalBlockId {
                hash: x.hash.clone(),
                part_set_header: x.part_set_header.as_ref().map(|y| CanonicalPartSetHeader {
                    total: y.total,
                    hash: y.hash.clone(),
                }),
            }),
            timestamp: proposal.timestamp.clone(),
            chain_id: self.chain_id.clone(),
        }
        .encode_length_delimited(&mut r)
        .expect("todo");
        r
        // self.to_signable_vec().expect("todo")
    }

    fn build_response(self, error: Option<RemoteSignerError>) -> Response {
        let response = if let Some(e) = error {
            SignedProposalResponse {
                proposal: None,
                error: Some(e),
            }
        } else {
            SignedProposalResponse {
                proposal: Some(SignProposalRequest::try_from(self).expect("fixme").proposal),
                error: None,
            }
        };

        Response::SignedProposal(response)
    }
}
