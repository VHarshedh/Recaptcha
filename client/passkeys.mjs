// Import from an application bundle. Use a button click for each operation.
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
async function request(path,body) {
  const response=await fetch('/passkeys/'+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),credentials:'same-origin'});
  const result=await response.json();
  if(!response.ok) throw new Error(result.error || 'Passkey request failed');
  return result;
}
export async function enrollPasskey(ticket) {
  const {id,options}=await request('register/options',{ticket});
  const response=await startRegistration({optionsJSON:options});
  return request('register/verify',{id,response});
}
export async function authenticatePasskey(action='login') {
  const {id,options}=await request('authenticate/options',{action});
  const response=await startAuthentication({optionsJSON:options});
  return request('authenticate/verify',{id,response});
}
