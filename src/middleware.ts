import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";
import { NextResponse } from "next/server";

/**
 * Clerk Middleware for Drafted Sports
 * Protects /admin routes with super_admin role check
 * Applies security headers to all responses
 */

// Routes that require super_admin authentication
const isAdminRoute = createRouteMatcher(["/admin(.*)", "/api/admin(.*)"]);

/**
 * Security headers applied to every response
 */
function addSecurityHeaders(response: NextResponse): NextResponse {
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  response.headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()"
  );
  response.headers.set(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob: https:",
      "media-src 'self' https://commondatastorage.googleapis.com",
      "connect-src 'self' https://www.espn.com",
      "frame-ancestors 'none'",
    ].join("; ")
  );
  return response;
}

export default clerkMiddleware(async (auth, req) => {
  // ── Admin route protection ────────────────────────────────
  if (isAdminRoute(req)) {
    // Get auth session
    const session = await auth();

    // Check if user is authenticated
    if (!session.userId) {
      // Redirect to Clerk sign-in
      const signInUrl = new URL("/sign-in", req.url);
      signInUrl.searchParams.set("redirect_url", req.nextUrl.pathname);
      return addSecurityHeaders(NextResponse.redirect(signInUrl));
    }

    // Get the user's role from Clerk metadata
    const userRole = session.user?.publicMetadata?.role as string | undefined;

    // Check if user has super_admin role
    if (userRole !== "super_admin") {
      // For API routes, return 401
      if (req.nextUrl.pathname.startsWith("/api/admin")) {
        return addSecurityHeaders(
          NextResponse.json(
            { error: "Unauthorized: super_admin role required" },
            { status: 401 }
          )
        );
      }

      // For UI routes, redirect to home
      return addSecurityHeaders(NextResponse.redirect(new URL("/", req.url)));
    }
  }

  // ── Security headers on all responses ────────────────────
  return addSecurityHeaders(NextResponse.next());
});

export const config = {
  matcher: [
    // Skip Next.js internals and static files
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)",
  ],
};
