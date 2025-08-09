// src/sol_icp_poc_frontend/assets/sol_icp_poc_backend.idl.js
import { IDL } from "@dfinity/candid";

export const idlFactory = ({ IDL }) =>
  IDL.Service({
    // query methods
    get_deposit_address: IDL.Func([IDL.Text], [IDL.Text], ['query']),
    get_nonce: IDL.Func([IDL.Text], [IDL.Nat64], ['query']),
    get_pid: IDL.Func([IDL.Text], [IDL.Text], ['query']),

    // update methods
    get_balance: IDL.Func([IDL.Text], [IDL.Nat64], []),
    transfer: IDL.Func(
      [IDL.Text, IDL.Nat64, IDL.Text, IDL.Vec(IDL.Nat8), IDL.Nat64],
      [IDL.Text],
      []
    ),
    get_sol_deposit_address: IDL.Func([IDL.Text], [IDL.Text], []),
    get_sol_balance: IDL.Func([IDL.Text], [IDL.Nat64], []),
    transfer_sol: IDL.Func(
      [IDL.Text, IDL.Nat64, IDL.Text, IDL.Vec(IDL.Nat8), IDL.Nat64],
      [IDL.Text],
      []
    ),
  });

export default idlFactory;
