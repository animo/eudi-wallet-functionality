import type { AgentContext, DcqlQuery } from '@credo-ts/core'
import { SdJwtVcService } from '@credo-ts/core'
import { type DcqlCredential, type DcqlQuery as Query, runDcqlQuery } from 'dcql'

export type AttributeBasedAccessControlPolicy = {
  attribute_based_access_control: DcqlQuery
}

export const validateAttributeBasedAccessControlPolicy = (
  agentContext: AgentContext,
  attributeBasedAccessControlPolicy: AttributeBasedAccessControlPolicy,
  authorizationAttestations: Array<string>
) => {
  const credentials: DcqlCredential[] = []
  const sdJwtService = agentContext.dependencyManager.resolve(SdJwtVcService)
  for (const authorizationAttestation of authorizationAttestations) {
    const sdJwtCredential = sdJwtService.fromCompact(authorizationAttestation)
    credentials.push({
      credential_format: 'dc+sd-jwt',
      vct: sdJwtCredential.prettyClaims.vct,
      claims: sdJwtCredential.prettyClaims,
    })
    credentials.push({
      credential_format: 'vc+sd-jwt',
      vct: sdJwtCredential.prettyClaims.vct,
      claims: sdJwtCredential.prettyClaims,
    })
  }

  const result = runDcqlQuery(attributeBasedAccessControlPolicy.attribute_based_access_control as Query.Output, {
    credentials,
    presentation: false,
  })

  return result.canBeSatisfied
}
