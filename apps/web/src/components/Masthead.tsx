import type { ReactNode } from 'react';

/**
 * The wordmark, and one line saying what the tool does.
 *
 * The person who commissioned this said twice that he could not tell what the
 * app was for. The screen said "Assay" and then went straight into a dense
 * ranked list, so the only way to know was to already know. The sentence has to
 * survive every top-level state, including the sign-in screen, which is the
 * literal first thing anyone sees and is rendered before a token exists.
 */
export function Masthead({ children }: { children?: ReactNode }) {
  return (
    <div className="brand">
      <h1>Assay</h1>
      <p className="top-sub">
        Finds the cryptography a quantum computer will break, and ranks every place it runs by how
        late it already is.
      </p>
      {children}
    </div>
  );
}
