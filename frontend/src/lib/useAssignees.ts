import { useEffect, useState } from 'react'

import { api, type Assignee } from '../api/client'

/** People who may own alerts and incidents (active analysts and admins). Loaded once per use. */
export function useAssignees(enabled: boolean): Assignee[] {
  const [list, setList] = useState<Assignee[]>([])
  useEffect(() => {
    if (!enabled) return
    let active = true
    api
      .assignees()
      .then((l) => active && setList(l))
      .catch(() => {
        /* the owner picker then offers only "unassigned" and the current owner */
      })
    return () => {
      active = false
    }
  }, [enabled])
  return list
}
