import {openAcquisitionObservations, AcquisitionEvent, ExternalPrincipalAttestation, AcquisitionInstallObservation} from '../bindings/node/index.js';
const observer=openAcquisitionObservations({path:'/protected/observations.state'});
declare const event:AcquisitionEvent;
declare const attestation:ExternalPrincipalAttestation;
declare const install:AcquisitionInstallObservation;
observer.append(event).then(result=>{const disposition:'APPENDED'|'DUPLICATE'|'CONFLICT'=result.disposition;void disposition;});
observer.attestExternalPrincipal(attestation);observer.recordInstallResult(install);
observer.export().then(rows=>rows[0].event.external_status_evidence);
observer.attestations();observer.snapshots();observer.scorecard({from:1,to_exclusive:2,as_of:3});
// @ts-expect-error caller cannot provide assigned arrival time
observer.append({...event,observed_at:1});
// @ts-expect-error fixed attestation statement prevents unrestricted claims
observer.attestExternalPrincipal({...attestation,statement:'proven independent controller'});
// @ts-expect-error input schema rejects arbitrary full receipt fields
observer.recordInstallResult({...install,raw_response:{private:true}});
