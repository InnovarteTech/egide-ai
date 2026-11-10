<?php

namespace App\Http\Controllers;

use App\Models\Finding;
use App\Models\Scan;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;

class EvidenceController extends Controller
{
    public function findingImage(Request $request, Finding $finding)
    {
        abort_unless(Scan::whereKey($finding->scan_id)->where('user_id', $request->user()->id)->exists(), 404);
        $path = 'findings/'.$finding->id.'.jpg';
        abort_unless(Storage::exists($path), 404);

        return Storage::response($path, 'achado.jpg', ['Content-Type' => 'image/jpeg', 'Cache-Control' => 'private, no-store']);
    }
}
