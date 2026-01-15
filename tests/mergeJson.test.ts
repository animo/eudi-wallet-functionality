import assert from 'node:assert'
import { describe, it } from 'node:test'
import { mergeJson } from '../src/mergeJson'

describe('mergeJson', () => {
  describe('Primitives', () => {
    it('should replace primitives', () => {
      assert.strictEqual(mergeJson(1, 2), 2)
      assert.strictEqual(mergeJson('a', 'b'), 'b')
      assert.strictEqual(mergeJson(true, false), false)
      assert.strictEqual(mergeJson(null, 1), 1)
      assert.strictEqual(mergeJson(1, null), null)
    })

    it('should handle undefined', () => {
      assert.strictEqual(mergeJson(1, undefined), 1)
      assert.strictEqual(mergeJson(undefined, 1), 1)
    })

    it('should replace mismatched types', () => {
      assert.strictEqual(mergeJson({ a: 1 }, 2), 2)
      assert.deepStrictEqual(mergeJson([1], { a: 1 }), { a: 1 })
    })
  })

  describe('Objects', () => {
    it('should merge objects by default', () => {
      const target = { a: 1, b: 2 }
      const source = { b: 3, c: 4 }
      assert.deepStrictEqual(mergeJson(target, source), { a: 1, b: 3, c: 4 })
    })

    it('should recursively merge objects', () => {
      const target = { a: { x: 1, y: 2 } }
      const source = { a: { y: 3, z: 4 } }
      assert.deepStrictEqual(mergeJson(target, source), { a: { x: 1, y: 3, z: 4 } })
    })

    it('should replace objects if configured', () => {
      const target = { a: { x: 1 } }
      const source = { a: { y: 2 } }
      const config = { objectStrategy: 'replace' as const }
      assert.deepStrictEqual(mergeJson(target, source, config), { a: { y: 2 } })
    })

    it('should replace specific fields if configured', () => {
      const target = { a: { x: 1 }, b: { x: 1 } }
      const source = { a: { y: 2 }, b: { y: 2 } }
      const config = {
        fields: {
          a: { strategy: 'replace' as const },
        },
      }
      assert.deepStrictEqual(mergeJson(target, source, config), {
        a: { y: 2 },
        b: { x: 1, y: 2 },
      })
    })
  })

  describe('Arrays', () => {
    it('should replace arrays by default', () => {
      const target = [1, 2]
      const source = [3, 4]
      assert.deepStrictEqual(mergeJson(target, source), [3, 4])
    })

    it('should append arrays if configured', () => {
      const target = [1, 2]
      const source = [3, 4]
      const config = { arrayStrategy: 'append' as const }
      assert.deepStrictEqual(mergeJson(target, source, config), [1, 2, 3, 4])
    })

    it('should merge arrays by index if configured', () => {
      const target = [{ id: 1, val: 'a' }, { id: 2 }]
      const source = [{ val: 'b' }]
      const config = { arrayStrategy: 'merge' as const }
      assert.deepStrictEqual(mergeJson(target, source, config), [{ id: 1, val: 'b' }, { id: 2 }])
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
        fields: {
          '': { arrayDiscriminant: 'id' },
        },
      }
      assert.deepStrictEqual(mergeJson(target, source, config), [
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
        fields: {
          '': { arrayDiscriminant: ['type', 'subtype'] },
        },
      }
      assert.deepStrictEqual(mergeJson(target, source, config), [
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
        fields: {
          '': { arrayDiscriminant: ['type', 'subtype'] },
        },
      }
      assert.deepStrictEqual(mergeJson(target, source, config), [
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

      assert.deepStrictEqual(mergeJson(target, source, config), {
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

      assert.notStrictEqual(result, target)
      assert.deepStrictEqual(target, { a: { b: 1 } })
      assert.deepStrictEqual(result, { a: { b: 1, c: 2 } })
    })

    it('should handle null values correctly', () => {
      const target = { a: 1, b: { c: 2 } }
      const source = { a: null, b: null }
      assert.deepStrictEqual(mergeJson(target, source), { a: null, b: null })
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

      assert.deepStrictEqual(result.users[0].profile, {
        name: 'Alice',
        settings: { theme: 'dark', notifications: true },
      })
      assert.deepStrictEqual(result.users[0].roles, ['editor']) // Default is replace
      assert.strictEqual(result.users[1].id, 2)
    })
  })
})
