import { createRouter, createWebHistory } from 'vue-router'

// Lazy load views for better performance
const Dashboard = () => import('../views/Dashboard.vue')
const ScanCreate = () => import('../views/ScanCreate.vue')
const JobsList = () => import('../views/JobsList.vue')
const JobDetail = () => import('../views/JobDetail.vue')
const ReportViewer = () => import('../views/ReportViewer.vue')
const WordlistManager = () => import('../views/WordlistManager.vue')

const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: Dashboard,
    meta: {
      title: 'Dashboard',
      icon: '📊',
    },
  },
  {
    path: '/scan/create',
    name: 'ScanCreate',
    component: ScanCreate,
    meta: {
      title: 'New Scan',
      icon: '🚀',
    },
  },
  {
    path: '/jobs',
    name: 'JobsList',
    component: JobsList,
    meta: {
      title: 'Jobs',
      icon: '📋',
    },
  },
  {
    path: '/job/:id',
    name: 'JobDetail',
    component: JobDetail,
    meta: {
      title: 'Job Details',
      icon: '🔍',
    },
  },
  {
    path: '/report/:id',
    name: 'ReportViewer',
    component: ReportViewer,
    meta: {
      title: 'Report',
      icon: '📄',
    },
  },
  {
    path: '/wordlists',
    name: 'WordlistManager',
    component: WordlistManager,
    meta: {
      title: 'Wordlists',
      icon: '📝',
    },
  },
  {
    path: '/:pathMatch(.*)*',
    redirect: '/',
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

// Navigation guard for page titles
router.beforeEach((to, from, next) => {
  document.title = to.meta.title
    ? `${to.meta.title} - Autosentou`
    : 'Autosentou - Automated Pentesting'
  next()
})

export default router
