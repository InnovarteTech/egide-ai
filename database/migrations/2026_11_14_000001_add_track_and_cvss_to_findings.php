<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('findings', function (Blueprint $table): void {
            $table->string('track', 20)->default('achado')->after('severity');
            $table->string('cvss_vector', 120)->nullable()->after('track');
            $table->decimal('cvss_score', 3, 1)->nullable()->after('cvss_vector');
        });
    }

    public function down(): void
    {
        Schema::table('findings', fn (Blueprint $table) => $table->dropColumn(['track', 'cvss_vector', 'cvss_score']));
    }
};
