import { AuthError } from "next-auth";
import { redirect } from "next/navigation";
import { auth, signIn } from "@/lib/auth";
import { Logo } from "@/components/logo";

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  if (await auth()) redirect("/admin");
  const { error } = await searchParams;
  return (
    <main className="grid min-h-screen place-items-center p-6">
      <div className="w-full max-w-md">
        <div className="mb-8 flex justify-center">
          <Logo />
        </div>
        <section className="panel p-7">
          <p className="eyebrow">Secure access</p>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight">
            Admin sign in
          </h1>
          <p className="mt-2 text-sm leading-6 text-slate-500">
            Access is restricted to administrators and auditors.
          </p>
          {error && (
            <div className="mt-5 rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-2 text-sm text-red-300">
              Invalid email or password.
            </div>
          )}
          <form
            className="mt-6 space-y-4"
            action={async (formData) => {
              "use server";
              try {
                await signIn("credentials", {
                  email: formData.get("email"),
                  password: formData.get("password"),
                  redirectTo: "/admin",
                });
              } catch (e) {
                if (e instanceof AuthError)
                  redirect("/login?error=credentials");
                throw e;
              }
            }}
          >
            <label className="block text-sm text-slate-300">
              Email
              <input
                className="input mt-2"
                name="email"
                type="email"
                autoComplete="email"
                required
              />
            </label>
            <label className="block text-sm text-slate-300">
              Password
              <input
                className="input mt-2"
                name="password"
                type="password"
                autoComplete="current-password"
                minLength={8}
                required
              />
            </label>
            <button className="button mt-2 w-full" type="submit">
              Sign in to Probeveil
            </button>
          </form>
        </section>
      </div>
    </main>
  );
}
