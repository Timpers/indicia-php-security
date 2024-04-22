<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SecurityHeaders
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle($request, Closure $next)
    {
     $response = $next($request);
     $response->headers->set('x-test-header', "This is a test");
     $response->headers->set('Content-Security-Policy', "default-src 'self'; script-src 'self'; frame-src 'none';style-src 'self' 'unsafe-inline' https://laravel.com https://fonts.bunny.net; img-src 'self' https://laravel.com; font-src 'self'; connect-src 'self'; media-src 'self'; object-src 'none'; child-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; block-all-mixed-content; upgrade-insecure-requests;");    
     $response->headers->set('X-Content-Type-Options', 'nosniff');
     $response->headers->remove('X-Test-Header');
     $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
     $response->headers->set('X-Frame-Options', 'DENY');    
     $response->headers->set('Referrer-Policy', 'no-referrer');
     return $response;
    }
}
