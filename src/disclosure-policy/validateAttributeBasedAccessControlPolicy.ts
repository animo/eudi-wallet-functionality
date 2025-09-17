import type { AgentContext, DcqlQuery, X509Certificate } from '@credo-ts/core'
import { SdJwtVcService } from '@credo-ts/core'
import { type DcqlCredential, DcqlQuery as Query } from 'dcql'
import { verifyAuthorizationAttestation } from './verifyAuthorizationAttestation'

export type AttributeBasedAccessControlPolicy = {
  attribute_based_access_control: DcqlQuery
}

type ValidateAttributeBasedAccessControlPolicyOptions = {
  attributeBasedAccessControlPolicy: AttributeBasedAccessControlPolicy
  authorizationAttestations: Array<string>
  accessCertificate: X509Certificate
  trustedCertificates?: Array<string>
  allowUntrustedSigned?: boolean
}

export const validateAttributeBasedAccessControlPolicy = async (
  agentContext: AgentContext,
  {
    accessCertificate,
    attributeBasedAccessControlPolicy,
    trustedCertificates,
    allowUntrustedSigned,
    authorizationAttestations,
  }: ValidateAttributeBasedAccessControlPolicyOptions
) => {
  try {
    const credentials: DcqlCredential[] = []
    const sdJwtService = agentContext.dependencyManager.resolve(SdJwtVcService)
    for (const authorizationAttestation of authorizationAttestations) {
      await verifyAuthorizationAttestation(agentContext, {
        authorizationAttestation,
        accessCertificate,
        allowUntrustedSigned,
        trustedCertificates,
      })
      const sdJwtCredential = sdJwtService.fromCompact(authorizationAttestation)
      credentials.push({
        credential_format: 'dc+sd-jwt',
        vct: sdJwtCredential.prettyClaims.vct,
        claims: sdJwtCredential.prettyClaims,
      })
    }

    const queryResult = Query.query(
      Query.parse(attributeBasedAccessControlPolicy.attribute_based_access_control),
      credentials
    )

    return queryResult.canBeSatisfied
  } catch {
    return false
  }
}
