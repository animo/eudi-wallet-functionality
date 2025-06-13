import type { DcqlQuery } from '@credo-ts/core'
import { isDcqlQueryEqualOrSubset } from './isDcqlQueryEqualOrSubset'

export const authorizeAttributeBasedAccessControl = (
  requestQuery: DcqlQuery,
  attributeBasedAccessControlQuery: DcqlQuery
) => isDcqlQueryEqualOrSubset(requestQuery, attributeBasedAccessControlQuery)
