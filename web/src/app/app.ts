import { Component, inject, OnInit, signal } from '@angular/core';
import { RouterOutlet, RouterLink, RouterLinkActive, Router, NavigationEnd } from '@angular/router';
import { filter } from 'rxjs/operators';
import { CommonModule } from '@angular/common';
import { MatSidenavModule } from '@angular/material/sidenav';
import { MatToolbarModule } from '@angular/material/toolbar';
import { MatListModule } from '@angular/material/list';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatMenuModule } from '@angular/material/menu';
import { MatDividerModule } from '@angular/material/divider';
import { FooterComponent } from './footer/footer.component';
import { AuthService } from './services/auth.service';

@Component({
  selector: 'app-root',
  imports: [
    CommonModule,
    RouterOutlet,
    RouterLink,
    RouterLinkActive,
    MatSidenavModule,
    MatToolbarModule,
    MatListModule,
    MatIconModule,
    MatButtonModule,
    MatMenuModule,
    MatDividerModule,
    FooterComponent
  ],
  templateUrl: './app.html',
  styleUrl: './app.scss'
})
export class App implements OnInit {
  private authService = inject(AuthService);
  private router = inject(Router);
  
  title = 'DNS Server Admin';
  isLoginPage = signal(false);
  
  isAuthenticated = this.authService.isAuthenticated;
  authEnabled = this.authService.authEnabled;
  currentUser = this.authService.currentUser;
  isAdmin = this.authService.isAdmin;
  isSuperAdmin = this.authService.isSuperAdmin;

  ngOnInit() {
    this.authService.checkAuthStatus().subscribe();
    
    // Check initial route
    this.isLoginPage.set(
      this.router.url === '/login' || 
      this.router.url === '/setup' || 
      this.router.url.startsWith('/auth/')
    );
    
    // Listen for route changes
    this.router.events.pipe(
      filter(event => event instanceof NavigationEnd)
    ).subscribe((event: NavigationEnd) => {
      this.isLoginPage.set(
        event.url === '/login' || 
        event.url === '/setup' || 
        event.url.startsWith('/auth/')
      );
    });
  }

  logout() {
    this.authService.logout().subscribe();
  }
}
