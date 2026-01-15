export type MergeStrategy = 'replace' | 'merge' | 'append'

export interface GlobalMergeConfig {
  /**
   * Default strategy for objects.
   * - 'merge': Recursively merge properties (default).
   * - 'replace': Replace the target object with the source object.
   */
  objectStrategy?: 'merge' | 'replace'

  /**
   * Default strategy for arrays.
   * - 'replace': Replace the target array with the source array (default).
   * - 'append': Append source elements to the target array.
   * - 'merge': Merge elements based on index or discriminant.
   */
  arrayStrategy?: 'replace' | 'append' | 'merge'

  /**
   * Global validator called for every field merge.
   * Defaults to `defaultValidator` which enforces strict type checking and prevents setting non-nullable values to null.
   */
  validator?: GlobalValidator
}

export interface MergeConfig extends GlobalMergeConfig {
  /**
   * Strategy for this specific field.
   */
  strategy?: MergeStrategy

  /**
   * If the field is an array and strategy is 'merge', this defines how to match elements.
   * - If string: The property name to use as a key (e.g., 'id').
   * - If array of strings: Composite key (e.g., ['type', 'subtype']).
   * - If undefined: Merge by index.
   */
  arrayDiscriminant?: string | string[]

  /**
   * Validator to check if the transition from target to source is allowed.
   * If the transition is invalid, this function should throw an error.
   * @param target The current value in the target.
   * @param source The new value from the source.
   */
  validate?: (target: unknown, source: unknown) => void

  /**
   * Nested configuration for properties of this field (if it is an object).
   */
  fields?: Record<string, MergeConfig>

  /**
   * Configuration for items of this field (if it is an array).
   */
  items?: MergeConfig
}

export type GlobalValidator = (path: string, target: unknown, source: unknown) => void

type Expand<T> = T extends infer O ? { [K in keyof O]: O[K] } : never

export type MergeResult<Target, Source, Config extends MergeConfig = Record<string, never>> = Source extends undefined // 1. Handle explicit undefined cases first
  ? Target
  : Target extends undefined
    ? Source
    : // 2. Unwrap types to check for Arrays
      NonNullable<Source> extends readonly unknown[]
      ? NonNullable<Target> extends readonly unknown[]
        ? Config['arrayStrategy'] extends 'append' | 'merge'
          ? Array<(Source extends readonly (infer S)[] ? S : never) | (Target extends readonly (infer T)[] ? T : never)>
          : Source
        : Source
      : // 3. Unwrap types to check for Objects
        NonNullable<Source> extends object
        ? NonNullable<Target> extends readonly unknown[]
          ? Source
          : // Target is array, Source is object -> Replace
            NonNullable<Target> extends object
            ? Config['objectStrategy'] extends 'replace'
              ? Source
              : Expand<
                  // 4. Use NonNullable for keyof operations to ensure we can iterate keys
                  {
                    [K in keyof NonNullable<Target> as K extends keyof NonNullable<Source>
                      ? never
                      : K]: NonNullable<Target>[K]
                  } & {
                    [K in keyof NonNullable<Source>]: K extends keyof NonNullable<Target>
                      ? MergeResult<NonNullable<Target>[K], NonNullable<Source>[K], Config>
                      : NonNullable<Source>[K]
                  }
                >
            : Source
        : Source

/**
 * Default validator that enforces:
 * 1. Non-null/undefined values cannot be set to null/undefined.
 * 2. Non-null/undefined types must match (e.g. cannot change string to number, or object to array).
 */
export const defaultValidator: GlobalValidator = (path, target, source) => {
  if (source === undefined) return
  if (target === undefined) return

  // 1. Non-null/undefined value cannot be set to null
  if (source === null) {
    if (target !== null) {
      throw new Error(`Invalid value change at path "${path}": cannot set non-nullable value to null`)
    }
    return
  }

  // 2. Non-null/undefined types are overridden/merged by the same type
  if (target === null) {
    // Target is null, source is not null. We allow this (null -> value).
    return
  }

  const targetType = getType(target)
  const sourceType = getType(source)

  if (targetType !== sourceType) {
    throw new Error(`Type mismatch at path "${path}": expected ${targetType}, got ${sourceType}`)
  }

  if (targetType === 'primitive') {
    if (typeof target !== typeof source) {
      throw new Error(`Type mismatch at path "${path}": expected ${typeof target}, got ${typeof source}`)
    }
  }
}

/**
 * Merges two JSON values based on a configuration.
 *
 * @param target The original object (will not be mutated).
 * @param source The object to merge into the target.
 * @param config Configuration for the merge behavior.
 * @returns The merged object.
 */
export function mergeJson<Target, Source, Config extends MergeConfig = MergeConfig>(
  target: Target,
  source: Source,
  config: Config = {} as Config
): MergeResult<Target, Source, Config> {
  const defaults: GlobalMergeConfig = {
    objectStrategy: config.objectStrategy,
    arrayStrategy: config.arrayStrategy,
    validator: config.validator ?? defaultValidator,
  }
  // Treat the root config as the node config for the root
  return mergeRecursive(target, source, config as MergeConfig, defaults, '') as MergeResult<Target, Source, Config>
}

function mergeRecursive(
  target: unknown,
  source: unknown,
  nodeConfig: MergeConfig | undefined,
  parentDefaults: GlobalMergeConfig,
  path: string
): unknown {
  // If types are different or one is null/undefined, source wins (unless source is undefined, then target wins)
  if (source === undefined) return target

  // Resolve effective defaults for this level (override parent defaults if present in nodeConfig)
  const currentDefaults: GlobalMergeConfig = {
    objectStrategy: nodeConfig?.objectStrategy ?? parentDefaults.objectStrategy,
    arrayStrategy: nodeConfig?.arrayStrategy ?? parentDefaults.arrayStrategy,
    validator: nodeConfig?.validator ?? parentDefaults.validator,
  }

  // Field-specific validation
  if (nodeConfig?.validate) {
    nodeConfig.validate(target, source)
  }

  // Global validation
  if (currentDefaults.validator) {
    currentDefaults.validator(path, target, source)
  }

  if (target === undefined) return source
  if (source === null) return null
  if (target === null) return source

  const targetType = getType(target)
  const sourceType = getType(source)

  // If validator passed but types mismatch, we assume source wins
  if (targetType !== sourceType) {
    return source
  }

  // Strict primitive check
  if (targetType === 'primitive') {
    if (typeof target !== typeof source) {
      return source
    }
    return source
  }

  const strategy = nodeConfig?.strategy

  // Handle Arrays
  if (sourceType === 'array') {
    const targetArray = target as unknown[]
    const sourceArray = source as unknown[]
    const arrayStrategy = strategy || currentDefaults.arrayStrategy || 'replace'

    if (arrayStrategy === 'replace') {
      return [...sourceArray]
    }

    if (arrayStrategy === 'append') {
      return [...targetArray, ...sourceArray]
    }

    if (arrayStrategy === 'merge') {
      return mergeArrays(
        targetArray,
        sourceArray,
        nodeConfig, // Pass current array config to mergeArrays
        currentDefaults,
        path,
        nodeConfig?.arrayDiscriminant
      )
    }
  }

  // Handle Objects
  if (sourceType === 'object') {
    const targetObj = target as Record<string, unknown>
    const sourceObj = source as Record<string, unknown>
    const objectStrategy = strategy || currentDefaults.objectStrategy || 'merge'

    if (objectStrategy === 'replace') {
      return { ...sourceObj }
    }

    if (objectStrategy === 'merge') {
      const result = { ...targetObj }
      const keys = new Set([...Object.keys(targetObj), ...Object.keys(sourceObj)])

      for (const key of keys) {
        // Use bracket notation if key contains invalid identifier characters
        const keyPart = /^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(key) ? `.${key}` : `["${key}"]`
        const newPath = path ? `${path}${keyPart}` : key

        // Resolve child config from nested fields
        const specificConfig = nodeConfig?.fields?.[key]
        const wildcardConfig = nodeConfig?.items

        // Merge specific config with wildcard config (specific takes precedence)
        const childNodeConfig =
          specificConfig && wildcardConfig
            ? { ...wildcardConfig, ...specificConfig }
            : (specificConfig ?? wildcardConfig)

        result[key] = mergeRecursive(targetObj[key], sourceObj[key], childNodeConfig, currentDefaults, newPath)
      }
      return result
    }
  }

  return source
}

function mergeArrays(
  target: unknown[],
  source: unknown[],
  arrayNodeConfig: MergeConfig | undefined,
  defaults: GlobalMergeConfig,
  path: string,
  discriminant?: string | string[]
): unknown[] {
  // The config for items comes from the 'items' property of the array's config
  const itemNodeConfig = arrayNodeConfig?.items

  if (!discriminant) {
    // Merge by index
    const result = [...target]
    for (let i = 0; i < source.length; i++) {
      if (i < result.length) {
        result[i] = mergeRecursive(result[i], source[i], itemNodeConfig, defaults, `${path}[${i}]`)
      } else {
        result.push(source[i])
      }
    }
    return result
  }

  // Merge by discriminant
  const result = [...target]
  const discriminants = Array.isArray(discriminant) ? discriminant : [discriminant]

  for (const sourceItem of source) {
    const matchIndex = result.findIndex((targetItem) => {
      if (getType(targetItem) !== 'object' || getType(sourceItem) !== 'object') return false
      const t = targetItem as Record<string, unknown>
      const s = sourceItem as Record<string, unknown>
      return discriminants.every((d) => deepEqual(t[d], s[d]))
    })

    if (matchIndex !== -1) {
      // Found a match, merge it
      result[matchIndex] = mergeRecursive(
        result[matchIndex],
        sourceItem,
        itemNodeConfig,
        defaults,
        `${path}[${matchIndex}]`
      )
    } else {
      // No match, append it
      result.push(sourceItem)
    }
  }

  return result
}

function getType(value: unknown): 'object' | 'array' | 'primitive' {
  if (Array.isArray(value)) return 'array'
  if (value !== null && typeof value === 'object') return 'object'
  return 'primitive'
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true

  const typeA = getType(a)
  const typeB = getType(b)

  if (typeA !== typeB) return false

  if (typeA === 'array') {
    const arrA = a as unknown[]
    const arrB = b as unknown[]
    if (arrA.length !== arrB.length) return false
    for (let i = 0; i < arrA.length; i++) {
      if (!deepEqual(arrA[i], arrB[i])) return false
    }
    return true
  }

  if (typeA === 'object') {
    const objA = a as Record<string, unknown>
    const objB = b as Record<string, unknown>
    const keysA = Object.keys(objA)
    const keysB = Object.keys(objB)

    if (keysA.length !== keysB.length) return false

    for (const key of keysA) {
      if (!Object.prototype.hasOwnProperty.call(objB, key)) return false
      if (!deepEqual(objA[key], objB[key])) return false
    }
    return true
  }

  return false
}
