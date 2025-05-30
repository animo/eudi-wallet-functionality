import { type AgentContext, deepEquality, equalsIgnoreOrder, equalsWithOrder } from '@credo-ts/core'

export function isDcqlQueryEqualOrSubset(
  agentContext: AgentContext,
  // @ts-ignore
  arq: DcqlQuery,
  // @ts-ignore
  rcq: DcqlQuery
): boolean {
  const dcqlService = agentContext.resolve(DcqlService)
  dcqlService.validateDcqlQuery(arq)
  // TODO: validate required the `id` property, which is not in the rcq
  // const rcqQuery = dcqlService.validateDcqlQuery(arq)

  if (rcq.credential_sets) {
    agentContext.config.logger.warn(
      'credential_sets are not allowed on the dcql query for the registration certificate'
    )
    return false
  }

  if (rcq.credentials.some((c) => c.id)) {
    agentContext.config.logger.warn(
      'credentials[n].id is not allowed on the dcql query for the registration certificate'
    )
    return false
  }

  // Short-circuit for exact match
  if (deepEquality(arq.credentials, rcq.credentials)) return true

  // only sd-jwt and mdoc are supported
  if (arq.credentials.some((c) => c.format !== 'mso_mdoc' && c.format !== 'vc+sd-jwt' && c.format !== 'dc+sd-jwt')) {
    return false
  }

  credentialQueryLoop: for (const credentialQuery of arq.credentials) {
    const matchingRcqCredentialQueriesBasedOnFormat = rcq.credentials.filter((c) => c.format === credentialQuery.format)

    if (matchingRcqCredentialQueriesBasedOnFormat.length === 0) return false

    switch (credentialQuery.format) {
      case 'mso_mdoc': {
        const doctypeValue = credentialQuery.meta?.doctype_value
        if (!doctypeValue) return false
        if (typeof credentialQuery.meta?.doctype_value !== 'string') return false

        const foundMatchingRequests = matchingRcqCredentialQueriesBasedOnFormat.filter(
          (c): c is typeof c & { format: 'mso_mdoc' } =>
            !!(c.format === 'mso_mdoc' && c.meta && c.meta.doctype_value === doctypeValue)
        )

        // We do not know which one we have to pick based on the meta+format
        if (foundMatchingRequests.length === 0) return false

        let foundFullyMatching = false
        for (const matchedRequest of foundMatchingRequests) {
          // credentialQuery.claims must match or be subset of matchedRequest

          // If the claims is empty, everything within the specific format+meta is allowed
          if (!matchedRequest.claims) continue credentialQueryLoop

          // If no specific claims are request, we allow it as the format+meta is allowed to be requested
          // but this requests no additional claims
          if (!credentialQuery.claims) continue credentialQueryLoop

          // Every claim request in the authorization request must be found in the registration certificate
          // for mdoc, this means matching the `path[0]` (namespace) and `path[1]` (value name)
          const isEveryClaimAllowedToBeRequested = credentialQuery.claims.every(
            (c) =>
              'path' in c &&
              matchedRequest.claims?.some(
                (mrc) => 'path' in mrc && c.path[0] === mrc.path[0] && c.path[1] === mrc.path[1]
              )
          )
          if (isEveryClaimAllowedToBeRequested) {
            foundFullyMatching = true
          }
        }

        if (!foundFullyMatching) return false

        break
      }
      case 'dc+sd-jwt':
      case 'vc+sd-jwt': {
        const vctValues = credentialQuery.meta?.vct_values
        if (!vctValues) return false
        if (credentialQuery.meta?.vct_values?.length === 0) return false

        const foundMatchingRequests = matchingRcqCredentialQueriesBasedOnFormat.filter(
          (c): c is typeof c & ({ format: 'dc+sd-jwt' } | { format: 'vc+sd-jwt' }) =>
            !!(
              (c.format === 'dc+sd-jwt' || c.format === 'vc+sd-jwt') &&
              c.meta?.vct_values &&
              equalsIgnoreOrder(c.meta.vct_values, vctValues)
            )
        )

        // We do not know which one we have to pick based on the meta+format
        if (foundMatchingRequests.length === 0) return false

        let foundFullyMatching = false
        for (const matchedRequest of foundMatchingRequests) {
          // credentialQuery.claims must match or be subset of matchedRequest

          // If the claims is empty, everything within the specific format+meta is allowed
          if (!matchedRequest.claims) continue credentialQueryLoop

          // If no specific claims are request, we allow it as the format+meta is allowed to be requested
          // but this requests no additional claims
          if (!credentialQuery.claims) continue credentialQueryLoop

          // Every claim request in the authorization request must be found in the registration certificate
          // for sd-jwt, this means making sure that every `path[n]` is in the registration certificate
          const isEveryClaimAllowedToBeRequested = credentialQuery.claims.every(
            (c) =>
              'path' in c && matchedRequest.claims?.some((mrc) => 'path' in mrc && equalsWithOrder(c.path, mrc.path))
          )
          if (isEveryClaimAllowedToBeRequested) {
            foundFullyMatching = true
          }
        }

        if (!foundFullyMatching) return false

        break
      }
      default:
        return false
    }
  }

  return true
}
