<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('targets', function (Blueprint $table): void {
            $table->string('safety', 20)->default('canario');
            $table->json('approved_writes')->nullable();
            $table->decimal('max_rps', 5, 2)->nullable();
            $table->text('focus')->nullable();
        });

        DB::table('targets')->where('environment_type', 'test')->update(['safety' => 'livre']);
    }

    public function down(): void
    {
        Schema::table('targets', fn (Blueprint $table) => $table->dropColumn(['safety', 'approved_writes', 'max_rps', 'focus']));
    }
};
