<?php

namespace App\Http\Middleware;

use App\Models\Workspace;
use Illuminate\Http\Request;
use Inertia\Middleware;

class HandleInertiaRequests extends Middleware
{
    public function share(Request $request): array
    {
        $user = $request->user();
        $workspace = $user ? Workspace::where('user_id', $user->id)->first() : null;

        return [
            ...parent::share($request),
            'auth' => $user?->only(['name', 'email', 'is_admin']),
            'workspace' => $workspace?->only(['name']),
            'flash' => fn () => $request->session()->get('notice'),
        ];
    }
}
