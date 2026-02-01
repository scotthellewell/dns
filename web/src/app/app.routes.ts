import { Routes } from '@angular/router';
import { DashboardComponent } from './dashboard/dashboard.component';
import { ZonesComponent } from './zones/zones.component';
import { RecordsComponent } from './records/records.component';
import { SecondaryZonesComponent } from './secondary-zones/secondary-zones.component';
import { TransferComponent } from './transfer/transfer.component';
import { RecursionComponent } from './recursion/recursion.component';
import { NetworkComponent } from './network/network.component';
import { LoginComponent } from './login/login.component';
import { ProfileComponent } from './profile/profile.component';
import { ApiKeysComponent } from './api-keys/api-keys.component';
import { SetupComponent } from './setup/setup.component';
import { TenantsComponent } from './tenants/tenants.component';
import { ClusterSyncComponent } from './cluster-sync/cluster-sync.component';
import { authGuard, loginGuard, adminGuard, setupGuard, superAdminGuard } from './guards/auth.guard';

export const routes: Routes = [
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
  { path: 'setup', component: SetupComponent, canActivate: [setupGuard] },
  { path: 'login', component: LoginComponent, canActivate: [loginGuard] },
  { path: 'auth/callback', component: LoginComponent }, // OIDC callback
  { path: 'dashboard', component: DashboardComponent, canActivate: [authGuard] },
  { path: 'zones', component: ZonesComponent, canActivate: [authGuard] },
  { path: 'records', component: RecordsComponent, canActivate: [authGuard] },
  { path: 'secondary-zones', component: SecondaryZonesComponent, canActivate: [authGuard] },
  { path: 'transfer', component: TransferComponent, canActivate: [authGuard] },
  { path: 'recursion', component: RecursionComponent, canActivate: [authGuard] },
  { path: 'network', component: NetworkComponent, canActivate: [adminGuard] },
  { path: 'cluster-sync', component: ClusterSyncComponent, canActivate: [adminGuard] },
  { path: 'tenants', component: TenantsComponent, canActivate: [superAdminGuard] },
  { path: 'profile', component: ProfileComponent, canActivate: [authGuard] },
  { path: 'api-keys', component: ApiKeysComponent, canActivate: [authGuard] },
];
