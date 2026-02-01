import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { ApiService, RecursionConfig } from '../services/api.service';

@Component({
  selector: 'app-recursion',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatCardModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatIconModule,
    MatSlideToggleModule,
    MatSelectModule,
    MatSnackBarModule
  ],
  templateUrl: './recursion.component.html',
  styleUrl: './recursion.component.scss'
})
export class RecursionComponent implements OnInit {
  config: RecursionConfig = {
    enabled: false,
    mode: 'partial',
    upstream: [],
    timeout: 5,
    max_depth: 10
  };
  
  modes = [
    { value: 'disabled', label: 'Disabled - No recursion' },
    { value: 'partial', label: 'Partial - Only for local records (CNAME, ALIAS)' },
    { value: 'full', label: 'Full - Open resolver (use with caution)' }
  ];
  
  newUpstream = '';
  
  loading = false;
  saving = false;

  constructor(
    private api: ApiService,
    private snackBar: MatSnackBar,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit() {
    this.loadConfig();
  }

  loadConfig() {
    this.loading = true;
    this.api.getRecursionConfig().subscribe({
      next: (config) => {
        this.config = config || {
          enabled: false,
          mode: 'partial',
          upstream: [],
          timeout: 5,
          max_depth: 10
        };
        // Ensure upstream is always an array
        if (!this.config.upstream) {
          this.config.upstream = [];
        }
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.snackBar.open('Failed to load recursion config', 'Close', { duration: 3000 });
        console.error(err);
        this.loading = false;
        this.cdr.detectChanges();
      }
    });
  }

  saveConfig() {
    this.saving = true;
    // Set enabled based on mode
    this.config.enabled = this.config.mode !== 'disabled';
    this.api.updateRecursionConfig(this.config).subscribe({
      next: () => {
        this.snackBar.open('Recursion settings saved', 'Close', { duration: 3000 });
        this.saving = false;
      },
      error: (err) => {
        this.snackBar.open('Failed to save settings', 'Close', { duration: 3000 });
        console.error(err);
        this.saving = false;
      }
    });
  }

  addUpstream() {
    if (this.newUpstream && !this.config.upstream!.includes(this.newUpstream)) {
      this.config.upstream!.push(this.newUpstream);
      this.newUpstream = '';
    }
  }

  removeUpstream(server: string) {
    this.config.upstream = this.config.upstream!.filter(s => s !== server);
  }
}
