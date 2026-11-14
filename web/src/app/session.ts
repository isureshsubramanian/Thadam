// The signed-in state, shared through context so any call that gets a 401 can end it.
import { createContext, useContext } from "react";

export const SignedOutContext = createContext<() => void>(() => undefined);

export const useSignedOut = (): (() => void) => useContext(SignedOutContext);
