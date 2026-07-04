export { auth as middleware } from "@/lib/auth";
export const config = { matcher: ["/((?!api/auth|api/internal|_next/static|_next/image|favicon.ico).*)"] };
