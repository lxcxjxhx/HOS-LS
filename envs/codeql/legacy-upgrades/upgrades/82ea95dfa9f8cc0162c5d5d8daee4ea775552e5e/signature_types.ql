class SignatureType extends @signature_type {
  string toString() { none() }
}

from SignatureType id, int kind, string tostring, int type_parameters, int required_params
where none()
select id, kind, tostring, type_parameters, required_params
