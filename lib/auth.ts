import { AuthOptions } from "next-auth"
import GitHubProvider from "next-auth/providers/github"

export const authOptions: AuthOptions = {
  providers: [
    GitHubProvider({
      clientId: process.env.GITHUB_ID!,
      clientSecret: process.env.GITHUB_SECRET!,
    }),
  ],
  pages: {
    signIn: "/login",
  },
  callbacks: {
    async jwt({ token, profile }) {
      if (profile) {
        token.login = (profile as { login?: string }).login
      }
      return token
    },
    async session({ session, token }) {
      if (session.user) {
        session.user.id = token.sub as string
        ;(session.user as { login?: string }).login = token.login as string
      }
      return session
    },
  },
}
