import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatDialogModule, MatDialog } from '@angular/material/dialog';
import { VersionService } from '../services/version.service';

@Component({
  selector: 'app-footer',
  standalone: true,
  imports: [
    CommonModule,
    MatIconModule,
    MatButtonModule,
    MatDialogModule
  ],
  templateUrl: './footer.component.html',
  styleUrl: './footer.component.scss'
})
export class FooterComponent {
  readonly versionService = inject(VersionService);
  currentYear = new Date().getFullYear();
  
  constructor(private dialog: MatDialog) {}
  
  openAttributions() {
    this.dialog.open(AttributionsDialogComponent, {
      width: '600px',
      maxHeight: '80vh'
    });
  }
}

@Component({
  selector: 'app-attributions-dialog',
  standalone: true,
  imports: [CommonModule, MatButtonModule, MatIconModule, MatDialogModule],
  template: `
    <h2 mat-dialog-title>Open Source Attributions</h2>
    <mat-dialog-content>
      <div class="attribution-intro">
        <p>This project uses the following open source software:</p>
      </div>
      
      <div class="attribution-section">
        <h3>Backend (Go)</h3>
        <div class="attribution-item">
          <strong>miekg/dns</strong>
          <span class="license">BSD-3-Clause</span>
          <p>DNS library for Go - provides DNS server and client capabilities</p>
          <a href="https://github.com/miekg/dns" target="_blank">github.com/miekg/dns</a>
        </div>
      </div>
      
      <div class="attribution-section">
        <h3>Frontend (Angular)</h3>
        <div class="attribution-item">
          <strong>Angular</strong>
          <span class="license">MIT</span>
          <p>Web application framework</p>
          <a href="https://angular.dev" target="_blank">angular.dev</a>
        </div>
        <div class="attribution-item">
          <strong>Angular Material</strong>
          <span class="license">MIT</span>
          <p>Material Design components for Angular</p>
          <a href="https://material.angular.io" target="_blank">material.angular.io</a>
        </div>
        <div class="attribution-item">
          <strong>RxJS</strong>
          <span class="license">Apache-2.0</span>
          <p>Reactive Extensions Library for JavaScript</p>
          <a href="https://rxjs.dev" target="_blank">rxjs.dev</a>
        </div>
      </div>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button mat-dialog-close>Close</button>
    </mat-dialog-actions>
  `,
  styles: [`
    mat-dialog-content {
      max-height: 60vh;
      overflow-y: auto;
    }
    
    .attribution-intro p {
      color: #94a3b8;
      margin-bottom: 16px;
    }
    
    .attribution-section {
      margin-bottom: 24px;
      
      h3 {
        color: #60a5fa;
        font-size: 14px;
        font-weight: 600;
        margin-bottom: 12px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
      }
    }
    
    .attribution-item {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 12px 16px;
      margin-bottom: 8px;
      
      strong {
        color: #f1f5f9;
        font-size: 14px;
      }
      
      .license {
        font-size: 11px;
        background: #334155;
        color: #94a3b8;
        padding: 2px 6px;
        border-radius: 4px;
        margin-left: 8px;
      }
      
      p {
        color: #94a3b8;
        font-size: 13px;
        margin: 8px 0;
      }
      
      a {
        color: #60a5fa;
        font-size: 12px;
        text-decoration: none;
        
        &:hover {
          text-decoration: underline;
        }
      }
    }
  `]
})
export class AttributionsDialogComponent {}
