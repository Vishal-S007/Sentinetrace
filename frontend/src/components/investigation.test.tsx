import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import type { NoteCreate } from '../api/client'
import { NoteComposer } from './investigation'

describe('NoteComposer', () => {
  it('keeps text typed while the previous note is saving', async () => {
    let release: () => void = () => {}
    const sent: NoteCreate[] = []
    render(
      <NoteComposer
        onSubmit={(body) => {
          sent.push(body)
          return new Promise<void>((resolve) => {
            release = resolve
          })
        }}
      />,
    )
    const box = screen.getByLabelText('Note text')
    await userEvent.type(box, 'first note')
    await userEvent.click(screen.getByRole('button', { name: 'Add to record' }))
    expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled()
    await userEvent.type(box, ' and more')
    release()
    expect(await screen.findByRole('button', { name: 'Add to record' })).toBeEnabled()
    expect(box).toHaveValue('first note and more')
    expect(sent).toEqual([{ kind: 'note', body: 'first note', event_id: null }])
  })

  it('clears the box after a save when nothing new was typed', async () => {
    render(<NoteComposer onSubmit={async () => {}} />)
    const box = screen.getByLabelText('Note text')
    await userEvent.type(box, 'done')
    await userEvent.click(screen.getByRole('button', { name: 'Add to record' }))
    expect(await screen.findByRole('button', { name: 'Add to record' })).toBeDisabled()
    expect(box).toHaveValue('')
  })
})
