import { describe, expect, it } from 'vitest'
import { mergeJson } from '../src/merge-json'

describe('mergeJson', () => {
  describe('Primitives', () => {
    it('should replace primitives', () => {
      expect(mergeJson(1, 2)).toBe(2)
      expect(mergeJson('a', 'b')).toBe('b')
      expect(mergeJson(true, false)).toBe(false)
    })

    it('should throw error when setting non-nullable to null', () => {
      expect(() => mergeJson(1, null)).toThrow(/cannot set non-nullable value to null/)
    })

    it('should allow setting null to value', () => {
      expect(mergeJson(null, 1)).toBe(1)
    })

    it('should handle undefined', () => {
      expect(mergeJson(1, undefined)).toBe(1)
      expect(mergeJson(undefined, 1)).toBe(1)
    })

    it('should throw error on mismatched types', () => {
      expect(() => mergeJson({ a: 1 }, 2)).toThrow(/Type mismatch/)
      expect(() => mergeJson([1], { a: 1 })).toThrow(/Type mismatch/)
      expect(() => mergeJson(1, 'a')).toThrow(/Type mismatch/)
    })
  })

  describe('Objects', () => {
    it('should merge objects by default', () => {
      const target = { a: 1, b: 2 }
      const source = { b: 3, c: 4 }
      expect(mergeJson(target, source)).toEqual({ a: 1, b: 3, c: 4 })
    })

    it('should recursively merge objects', () => {
      const target = { a: { x: 1, y: 2 } }
      const source = { a: { y: 3, z: 4 } }
      expect(mergeJson(target, source)).toEqual({ a: { x: 1, y: 3, z: 4 } })
    })

    it('should replace objects if configured', () => {
      const target = { a: { x: 1 } }
      const source = { a: { y: 2 } }
      const config = { objectStrategy: 'replace' as const }
      expect(mergeJson(target, source, config)).toEqual({ a: { y: 2 } })
    })

    it('should replace specific fields if configured', () => {
      const target = { a: { x: 1 }, b: { x: 1 } }
      const source = { a: { y: 2 }, b: { y: 2 } }
      const config = {
        fields: {
          a: { strategy: 'replace' as const },
        },
      }
      expect(mergeJson(target, source, config)).toEqual({
        a: { y: 2 },
        b: { x: 1, y: 2 },
      })
    })
  })

  describe('Arrays', () => {
    it('should replace arrays by default', () => {
      const target = [1, 2]
      const source = [3, 4]
      expect(mergeJson(target, source)).toEqual([3, 4])
    })

    it('should append arrays if configured', () => {
      const target = [1, 2]
      const source = [3, 4]
      const config = { arrayStrategy: 'append' as const }
      expect(mergeJson(target, source, config)).toEqual([1, 2, 3, 4])
    })

    it('should merge arrays by index if configured', () => {
      const target = [{ id: 1, val: 'a' }, { id: 2 }]
      const source = [{ val: 'b' }]
      const config = { arrayStrategy: 'merge' as const }
      expect(mergeJson(target, source, config)).toEqual([{ id: 1, val: 'b' }, { id: 2 }])
    })

    it('should merge arrays by discriminant (single key)', () => {
      const target = [
        { id: 1, val: 'a' },
        { id: 2, val: 'b' },
      ]
      const source = [
        { id: 2, val: 'c' }, // Update
        { id: 3, val: 'd' }, // New
      ]
      const config = {
        arrayStrategy: 'merge' as const,
        arrayDiscriminant: 'id',
      }
      expect(mergeJson(target, source, config)).toEqual([
        { id: 1, val: 'a' },
        { id: 2, val: 'c' },
        { id: 3, val: 'd' },
      ])
    })

    it('should merge arrays by discriminant (composite key)', () => {
      const target = [
        { type: 'A', subtype: '1', val: 'x' },
        { type: 'A', subtype: '2', val: 'y' },
      ]
      const source = [
        { type: 'A', subtype: '1', val: 'z' }, // Update
        { type: 'B', subtype: '1', val: 'w' }, // New
      ]
      const config = {
        arrayStrategy: 'merge' as const,
        arrayDiscriminant: ['type', 'subtype'],
      }
      expect(mergeJson(target, source, config)).toEqual([
        { type: 'A', subtype: '1', val: 'z' },
        { type: 'A', subtype: '2', val: 'y' },
        { type: 'B', subtype: '1', val: 'w' },
      ])
    })

    it('should merge arrays by discriminant (composite key with optional/undefined values)', () => {
      const target = [
        { type: 'A', subtype: '1', val: 'x' },
        { type: 'A', val: 'y' }, // subtype undefined
        { type: 'B', subtype: undefined, val: 'z' },
      ]
      const source = [
        { type: 'A', subtype: '1', val: 'x-updated' }, // Match
        { type: 'A', val: 'y-updated' }, // Match (subtype undefined === undefined)
        { type: 'B', subtype: undefined, val: 'z-updated' }, // Match
        { type: 'A', subtype: '2', val: 'new' }, // No match
      ]
      const config = {
        arrayStrategy: 'merge' as const,
        arrayDiscriminant: ['type', 'subtype'],
      }
      expect(mergeJson(target, source, config)).toEqual([
        { type: 'A', subtype: '1', val: 'x-updated' },
        { type: 'A', val: 'y-updated' },
        { type: 'B', subtype: undefined, val: 'z-updated' },
        { type: 'A', subtype: '2', val: 'new' },
      ])
    })

    it('should handle nested array merging', () => {
      const target = {
        items: [{ id: 1, tags: ['a'] }],
      }
      const source = {
        items: [{ id: 1, tags: ['b'] }],
      }
      const config = {
        fields: {
          items: {
            strategy: 'merge' as const,
            arrayDiscriminant: 'id',
          },
        },
      }

      expect(mergeJson(target, source, config)).toEqual({
        items: [
          { id: 1, tags: ['b'] }, // tags replaced
        ],
      })
    })
  })

  describe('Deep Merging & Edge Cases', () => {
    it('should not mutate target', () => {
      const target = { a: { b: 1 } }
      const source = { a: { c: 2 } }
      const result = mergeJson(target, source)

      expect(result).not.toBe(target)
      expect(target).toEqual({ a: { b: 1 } })
      expect(result).toEqual({ a: { b: 1, c: 2 } })
    })

    it('should handle null values correctly', () => {
      const target = { a: 1, b: { c: 2 } }
      const source = { a: null, b: null }
      // Expect error because target.a is 1 (non-null) and source.a is null
      expect(() => mergeJson(target, source)).toThrow(/cannot set non-nullable value to null/)
    })

    it('should handle complex nested structure with discriminants', () => {
      const target = {
        users: [
          {
            id: 1,
            profile: { name: 'Alice', settings: { theme: 'dark' } },
            roles: ['admin'],
          },
        ],
      }
      const source = {
        users: [
          {
            id: 1,
            profile: { settings: { notifications: true } },
            roles: ['editor'],
          },
          {
            id: 2,
            profile: { name: 'Bob' },
          },
        ],
      }

      const config = {
        fields: {
          users: { strategy: 'merge' as const, arrayDiscriminant: 'id' },
        },
      }

      const result = mergeJson(target, source, config)

      expect(result.users[0].profile).toEqual({
        name: 'Alice',
        settings: { theme: 'dark', notifications: true },
      })
      expect(result.users[0].roles).toEqual(['editor']) // Default is replace
      expect(result.users[1].id).toBe(2)
    })
  })
})
