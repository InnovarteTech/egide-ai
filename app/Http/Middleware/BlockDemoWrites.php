<?php

namespace App\Http\Middleware;

use App\Models\Workspace;
use Closure;
use Illuminate\Http\Request;

class BlockDemoWrites
{
    public function handle(Request $request, Closure $next)
    {
        if (! $request->isMethodSafe() && $request->user()
            && Workspace::where('user_id', $request->user()->id)->where('demo', true)->exists()) {
            return back()->with('notice', 'Na demonstração pública você pode explorar e rodar o laboratório. Para cadastrar ambientes, tokens, webhooks e monitores, crie uma conta.');
        }

        return $next($request);
    }
}
