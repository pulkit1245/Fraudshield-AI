// TanStack Query wrappers around the auth context — gives LoginPage tidy
// loading/error state for the login mutation. Owner: Member D.
import { useMutation } from "@tanstack/react-query";
import { useAuth } from "../context/AuthContext";

export { useAuth } from "../context/AuthContext";

export interface LoginVars {
  email: string;
  password: string;
}

export function useLoginMutation() {
  const { login } = useAuth();
  return useMutation({
    mutationFn: ({ email, password }: LoginVars) => login(email, password),
  });
}
