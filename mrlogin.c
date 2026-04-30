/* MrLogin - Display Manager for MrRobotOS
 * Compile:
 *   gcc -std=c99 -Wall -Os \
 *     -I/usr/include/freetype2 \
 *     $(pkg-config --cflags gdk-pixbuf-2.0 cairo cairo-xlib) \
 *     -o mrlogin mrlogin.c \
 *     -lX11 -lXft -lXext -lpam -lXss \
 *     $(pkg-config --libs gdk-pixbuf-2.0 cairo cairo-xlib)
 * Maintainer: Bora Poçan <borapocan@github.com>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xatom.h>
#include <X11/keysym.h>
#include <X11/Xft/Xft.h>
#include <X11/extensions/scrnsaver.h>
#include <security/pam_appl.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <cairo/cairo.h>
#include <cairo/cairo-xlib.h>

/* appearance */
#define CARD_W          520
#define CARD_H          480
#define CARD_R          18
#define INPUT_H         58
#define INPUT_R         10
#define AVATAR_R        60
#define ARROW_W         38
#define ARROW_H         38
#define BG_COLOR        "#0a0a0c"
#define CARD_COLOR      "#161618"
#define INPUT_FOCUS     "#2a2a2c"
#define ACCENT          "#e63946"
#define ACCENT2         "#c1121f"
#define ARROW_COLOR     "#1e1e20"
#define TEXT_COLOR      "#f0f0f0"
#define TEXT_DIM        "#6e6e73"
#define TEXT_MID        "#aeaeb2"
#define ERROR_COLOR     "#ff453a"
#define SEPARATOR       "#2c2c2e"
#define AVATAR_BG       "#111114"
#define FONT_TITLE      "monospace:size=17:bold"
#define FONT_SUBTITLE   "monospace:size=11"
#define FONT_INPUT      "monospace:size=16"
#define FONT_LABEL      "monospace:size=12"
#define FONT_CLOCK      "monospace:size=56:bold"
#define FONT_DATE       "monospace:size=15"
#define FONT_USER       "monospace:size=13"
#define FONT_BRAND      "monospace:size=38:bold"
#define FONT_FA         "Font Awesome 7 Free Solid:size=16"
#define FONT_FA_LG      "Font Awesome 7 Free Solid:size=20"
#define FONT_FA_AVT     "Font Awesome 7 Free Solid:size=36"
#define MIN_UID         1000
#define MAX_USERS       32
#define IDLE_TIMEOUT_SEC 300
#define IDLE_CHECK_MS    10000
#define LOGO_PATH       "/usr/share/icons/mrrobotos/512x512/apps/mrlogin.png"
#define LOGO_HEIGHT     96
#define BRAND_NAME      "Mr.RobotOS"
#define SUCCESS_COLOR   "#30d158"

/* layout constants */
#define MID_GAP_TOP  20
#define NAME_H       22
#define MID_GAP_BOT  16
#define BOT_PAD_TOP  18

/* state */
static int  lock_mode = 0;
static int  root_mode = 0;
static char lock_user[64] = "";

typedef struct {
    char  name[64];
    char  home[512];
    char  shell[256];
    uid_t uid;
    gid_t gid;
    char  avatar_path[1024];
} UserInfo;

static UserInfo users[MAX_USERS];
static int      nusers    = 0;
static int      sel_user  = 0;
static int      fail_count = 0;
static int      show_pass  = 0;
static int      eye_x=0, eye_y=0, eye_w=0, eye_h=0;
static int      arr_l_x=0, arr_l_y=0;
static int      arr_r_x=0, arr_r_y=0;
static int      cursor_visible = 1;
#define CURSOR_BLINK_MS 530

static cairo_surface_t *avatar_surf[MAX_USERS];
static int              avatar_loaded[MAX_USERS];
static cairo_surface_t *lock_avatar_surf = NULL;
static int              lock_avatar_done = 0;
static cairo_surface_t *logo_surf   = NULL;
static int              logo_surf_w = 0, logo_surf_h = 0;

static Display *dpy;
static Window   root_win, win;
static int      screen;
static Pixmap   buf;
static GC       gc;
static XftDraw *xdraw;
static XftFont *font_title, *font_subtitle, *font_input, *font_label;
static XftFont *font_clock, *font_date, *font_user, *font_brand;
static XftFont *font_fa, *font_fa_lg, *font_fa_avt;
static Colormap cmap;
static Visual  *vis;
static int      sw, sh;
static int      ss_event_base, ss_error_base;
static int      has_scrnsaver = 0;

static char pass_buf[256] = "";
static int  pass_len      = 0;
static char error_msg[256]= "";
static int  auth_ok            = 0;
static int  auth_success_shown = 0;

#define FA_LOCK      "\xef\x80\xa3"
#define FA_EYE       "\xef\x80\xae"
#define FA_EYE_SLASH "\xef\x81\xb0"
#define FA_ARROW     "\xef\x81\xa1"
#define FA_USER      "\xef\x80\x87"
#define FA_WARNING   "\xef\x81\xb1"
#define FA_CHECK     "\xef\x80\x8c"
#define FA_CHEVRON_L "\xef\x81\x93"
#define FA_CHEVRON_R "\xef\x81\x94"

#define LOG_INFO_MSG(fmt,...) syslog(LOG_INFO,    "mrlogin: " fmt, ##__VA_ARGS__)
#define LOG_WARN_MSG(fmt,...) syslog(LOG_WARNING, "mrlogin: " fmt, ##__VA_ARGS__)
#define LOG_ERR_MSG(fmt,...)  syslog(LOG_ERR,     "mrlogin: " fmt, ##__VA_ARGS__)

/* PAM */
static const char   *pam_password = NULL;
static pam_handle_t *global_pamh  = NULL;

static int pam_conv_func(int num_msg, const struct pam_message **msg,
                         struct pam_response **resp, void *appdata) {
    (void)appdata;
    *resp = calloc(num_msg, sizeof(struct pam_response));
    if (!*resp) return PAM_BUF_ERR;
    for (int i = 0; i < num_msg; i++)
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF ||
            msg[i]->msg_style == PAM_PROMPT_ECHO_ON)
            (*resp)[i].resp = strdup(pam_password ? pam_password : "");
    return PAM_SUCCESS;
}

static int authenticate(const char *user, const char *pass) {
    if (global_pamh) {
        pam_close_session(global_pamh, 0);
        pam_end(global_pamh, PAM_SUCCESS);
        global_pamh = NULL;
    }
    pam_password = pass;
    struct pam_conv conv = { pam_conv_func, NULL };
    int ret = pam_start("mrlogin", user, &conv, &global_pamh);
    if (ret != PAM_SUCCESS) {
        LOG_ERR_MSG("pam_start failed: %s", pam_strerror(global_pamh, ret));
        goto fail;
    }
    ret = pam_authenticate(global_pamh, 0);
    if (ret != PAM_SUCCESS) {
        LOG_WARN_MSG("pam_authenticate failed for %s: %s", user, pam_strerror(global_pamh, ret));
        goto fail;
    }
    /* pam_acct_mgmt: skip for root, treat expired password as ok for others */
    ret = pam_acct_mgmt(global_pamh, PAM_SILENT);
    if (ret != PAM_SUCCESS && ret != PAM_NEW_AUTHTOK_REQD) {
        if (strcmp(user, "root") != 0) {
            LOG_WARN_MSG("pam_acct_mgmt failed for %s: %s", user, pam_strerror(global_pamh, ret));
            goto fail;
        }
    }
    ret = pam_open_session(global_pamh, 0);
    if (ret != PAM_SUCCESS) {
        LOG_WARN_MSG("pam_open_session failed for %s: %s", user, pam_strerror(global_pamh, ret));
        goto fail;
    }
    { char **e = pam_getenvlist(global_pamh);
      if (e) for (int i = 0; e[i]; i++) putenv(e[i]); }
    LOG_INFO_MSG("authenticated user %s", user);
    return 1;
fail:
    if (global_pamh) { pam_end(global_pamh, ret); global_pamh = NULL; }
    return 0;
}

/* image loading */
static void pixbuf_to_cairo_surface(GdkPixbuf *pb, cairo_surface_t *surf,
                                    int dest_w, int dest_h) {
    int n_ch = gdk_pixbuf_get_n_channels(pb);
    int row_stride = gdk_pixbuf_get_rowstride(pb);
    guchar *pixels = gdk_pixbuf_get_pixels(pb);
    unsigned char *dst = cairo_image_surface_get_data(surf);
    int dst_stride = cairo_image_surface_get_stride(surf);
    int has_alpha  = gdk_pixbuf_get_has_alpha(pb);
    cairo_surface_flush(surf);
    for (int y = 0; y < dest_h; y++) {
        guchar        *src_row = pixels + y * row_stride;
        unsigned char *dst_row = dst    + y * dst_stride;
        for (int x = 0; x < dest_w; x++) {
            guchar r2=src_row[x*n_ch+0], g2=src_row[x*n_ch+1], b2=src_row[x*n_ch+2];
            guchar a2 = has_alpha ? src_row[x*n_ch+3] : 255u;
            dst_row[x*4+0]=(unsigned char)((unsigned)b2*a2/255u);
            dst_row[x*4+1]=(unsigned char)((unsigned)g2*a2/255u);
            dst_row[x*4+2]=(unsigned char)((unsigned)r2*a2/255u);
            dst_row[x*4+3]=a2;
        }
    }
    cairo_surface_mark_dirty(surf);
}

static cairo_surface_t *load_avatar_surface(const char *path, int r) {
    int diam = r * 2;
    GError *err = NULL;
    GdkPixbuf *pb = gdk_pixbuf_new_from_file(path, &err);
    if (!pb) {
        if (err) { g_error_free(err); err = NULL; }
        static const char *exts[] = {
            ".jpg",".jpeg",".JPG",".JPEG",".png",".PNG",".webp",".WEBP",NULL };
        char tried[1040];
        for (int i = 0; exts[i] && !pb; i++) {
            snprintf(tried, sizeof(tried), "%s%s", path, exts[i]);
            pb = gdk_pixbuf_new_from_file(tried, &err);
            if (!pb && err) { g_error_free(err); err = NULL; }
        }
    }
    if (!pb) { LOG_WARN_MSG("avatar: could not load '%s'", path); return NULL; }
    int pw2=gdk_pixbuf_get_width(pb), ph2=gdk_pixbuf_get_height(pb);
    double scale=(pw2<ph2)?(double)diam/pw2:(double)diam/ph2;
    int sw2=(int)(pw2*scale+0.5), sh2=(int)(ph2*scale+0.5);
    if (sw2<1) sw2=1;
    if (sh2<1) sh2=1;
    GdkPixbuf *scaled=gdk_pixbuf_scale_simple(pb,sw2,sh2,GDK_INTERP_BILINEAR);
    g_object_unref(pb);
    if (!scaled) return NULL;
    int ox=(sw2-diam)/2, oy=(sh2-diam)/2;
    if (ox<0) ox=0;
    if (oy<0) oy=0;
    GdkPixbuf *cropped=gdk_pixbuf_new_subpixbuf(scaled,ox,oy,diam,diam);
    g_object_unref(scaled);
    if (!cropped) return NULL;
    cairo_surface_t *surf=cairo_image_surface_create(CAIRO_FORMAT_ARGB32,diam,diam);
    if (cairo_surface_status(surf)!=CAIRO_STATUS_SUCCESS) {
        g_object_unref(cropped); cairo_surface_destroy(surf); return NULL; }
    pixbuf_to_cairo_surface(cropped,surf,diam,diam);
    g_object_unref(cropped);
    LOG_INFO_MSG("avatar loaded: %s r=%d", path, r);
    return surf;
}

static void draw_cairo_circle(cairo_surface_t *img_surf, int ax, int ay, int r) {
    double pi2=2.0*3.14159265358979323846;
    cairo_surface_t *xsurf=cairo_xlib_surface_create(dpy,buf,vis,sw,sh);
    cairo_t *cr=cairo_create(xsurf);
    cairo_arc(cr,(double)ax,(double)ay,(double)r,0,pi2);
    cairo_clip(cr);
    cairo_set_source_surface(cr,img_surf,(double)(ax-r),(double)(ay-r));
    cairo_paint(cr);
    cairo_reset_clip(cr);
    XColor xc; XParseColor(dpy,cmap,ACCENT,&xc);
    cairo_arc(cr,(double)ax,(double)ay,(double)(r-1),0,pi2);
    cairo_set_source_rgba(cr,xc.red/65535.0,xc.green/65535.0,xc.blue/65535.0,0.9);
    cairo_set_line_width(cr,2.5);
    cairo_stroke(cr);
    cairo_destroy(cr); cairo_surface_destroy(xsurf);
}

static void load_avatars(void) {
    for (int i=0; i<nusers; i++) {
        avatar_surf[i]=NULL; avatar_loaded[i]=0;
        if (!users[i].avatar_path[0]) continue;
        avatar_surf[i]=load_avatar_surface(users[i].avatar_path,AVATAR_R);
        avatar_loaded[i]=(avatar_surf[i]!=NULL);
    }
}

static void load_logo(void) {
    GError *err=NULL;
    GdkPixbuf *pb=gdk_pixbuf_new_from_file(LOGO_PATH,&err);
    if (!pb) { if (err) { LOG_WARN_MSG("logo: %s",err->message); g_error_free(err); } return; }
    int ow=gdk_pixbuf_get_width(pb),oh=gdk_pixbuf_get_height(pb),tw=ow*LOGO_HEIGHT/oh;
    GdkPixbuf *scaled=gdk_pixbuf_scale_simple(pb,tw,LOGO_HEIGHT,GDK_INTERP_BILINEAR);
    g_object_unref(pb); if (!scaled) return;
    logo_surf=cairo_image_surface_create(CAIRO_FORMAT_ARGB32,tw,LOGO_HEIGHT);
    if (cairo_surface_status(logo_surf)!=CAIRO_STATUS_SUCCESS) {
        cairo_surface_destroy(logo_surf); logo_surf=NULL; g_object_unref(scaled); return; }
    pixbuf_to_cairo_surface(scaled,logo_surf,tw,LOGO_HEIGHT);
    g_object_unref(scaled); logo_surf_w=tw; logo_surf_h=LOGO_HEIGHT;
}

/* user enumeration */
static void get_users(void) {
    if (root_mode) {
        struct passwd *pw=getpwnam("root");
        if (pw) {
            strncpy(users[0].name, pw->pw_name, 63);
            strncpy(users[0].home, pw->pw_dir,  255);
            strncpy(users[0].shell,pw->pw_shell,255);
            users[0].uid=pw->pw_uid; users[0].gid=pw->pw_gid;
            /* /root/.config/mrrobotos/account/avatar */
            snprintf(users[0].avatar_path,sizeof(users[0].avatar_path),
                     "%s/.config/mrrobotos/mrsettings/account/avatar",pw->pw_dir);
            nusers=1;
            LOG_INFO_MSG("root mode: avatar=%s",users[0].avatar_path);
        }
        return;
    }
    struct passwd *pw;
    setpwent();
    while ((pw=getpwent())&&nusers<MAX_USERS) {
        if (pw->pw_uid<MIN_UID) continue;
        if (strcmp(pw->pw_name,"nobody")==0) continue;
        if (strcmp(pw->pw_shell,"/sbin/nologin")==0) continue;
        if (strcmp(pw->pw_shell,"/bin/false")==0) continue;
        if (strcmp(pw->pw_shell,"/usr/bin/nologin")==0) continue;
        struct stat st; if (stat(pw->pw_dir,&st)!=0) continue;
        strncpy(users[nusers].name, pw->pw_name, 63);
        strncpy(users[nusers].home, pw->pw_dir,  255);
        strncpy(users[nusers].shell,pw->pw_shell,255);
        users[nusers].uid=pw->pw_uid; users[nusers].gid=pw->pw_gid;
        snprintf(users[nusers].avatar_path,sizeof(users[nusers].avatar_path),
                 "%s/.config/mrrobotos/mrsettings/account/avatar",pw->pw_dir);
        nusers++;
    }
    endpwent();
    if (nusers==0) {
        pw=getpwnam("root");
        if (pw) {
            strncpy(users[0].name, pw->pw_name, 63);
            strncpy(users[0].home, pw->pw_dir,  255);
            strncpy(users[0].shell,pw->pw_shell,255);
            users[0].uid=pw->pw_uid; users[0].gid=pw->pw_gid;
            snprintf(users[0].avatar_path,sizeof(users[0].avatar_path),
                     "%s/.config/mrrobotos/mrsettings/account/avatar",pw->pw_dir);
            nusers=1; LOG_WARN_MSG("no regular users, falling back to root");
        }
    }
}

static unsigned long get_idle_ms(void) {
    if (!has_scrnsaver) return 0;
    XScreenSaverInfo *info=XScreenSaverAllocInfo(); if (!info) return 0;
    XScreenSaverQueryInfo(dpy,root_win,info);
    unsigned long idle=info->idle; XFree(info); return idle;
}

static void get_primary_monitor(void) {
    sw=DisplayWidth(dpy,screen); sh=DisplayHeight(dpy,screen);
    FILE *f=popen("xrandr 2>/dev/null | grep ' connected primary' | "
                  "grep -o '[0-9]*x[0-9]*+[0-9]*+[0-9]*'","r");
    if (!f) return;
    int w,h,x,y; if (fscanf(f,"%dx%d+%d+%d",&w,&h,&x,&y)==4){sw=w;sh=h;} pclose(f);
}

typedef struct { const char *hex; unsigned long pixel; } ColorEntry;
static ColorEntry color_cache[64];
static int        color_cache_n=0;

static unsigned long mkcolor(const char *hex) {
    for (int i=0;i<color_cache_n;i++) if (strcmp(color_cache[i].hex,hex)==0) return color_cache[i].pixel;
    XColor c; XParseColor(dpy,cmap,hex,&c); XAllocColor(dpy,cmap,&c);
    if (color_cache_n<64){color_cache[color_cache_n].hex=hex;color_cache[color_cache_n].pixel=c.pixel;color_cache_n++;}
    return c.pixel;
}
static void xftcolor(XftColor *out,const char *hex){XftColorAllocName(dpy,vis,cmap,hex,out);}

static void fill_rounded(int x,int y,int w,int h,int r){
    if(r<1){XFillRectangle(dpy,buf,gc,x,y,w,h);return;}
    XFillRectangle(dpy,buf,gc,x+r,y,w-2*r,h); XFillRectangle(dpy,buf,gc,x,y+r,w,h-2*r);
    XFillArc(dpy,buf,gc,x,y,2*r,2*r,90*64,90*64); XFillArc(dpy,buf,gc,x+w-2*r,y,2*r,2*r,0,90*64);
    XFillArc(dpy,buf,gc,x,y+h-2*r,2*r,2*r,180*64,90*64); XFillArc(dpy,buf,gc,x+w-2*r,y+h-2*r,2*r,2*r,270*64,90*64);
}
static void stroke_rounded(int x,int y,int w,int h,int r){
    XDrawArc(dpy,buf,gc,x,y,2*r,2*r,90*64,90*64); XDrawArc(dpy,buf,gc,x+w-2*r,y,2*r,2*r,0,90*64);
    XDrawArc(dpy,buf,gc,x,y+h-2*r,2*r,2*r,180*64,90*64); XDrawArc(dpy,buf,gc,x+w-2*r,y+h-2*r,2*r,2*r,270*64,90*64);
    XDrawLine(dpy,buf,gc,x+r,y,x+w-r,y); XDrawLine(dpy,buf,gc,x+r,y+h,x+w-r,y+h);
    XDrawLine(dpy,buf,gc,x,y+r,x,y+h-r); XDrawLine(dpy,buf,gc,x+w,y+r,x+w,y+h-r);
}
static int text_w(XftFont *f,const char *s){XGlyphInfo e;XftTextExtentsUtf8(dpy,f,(FcChar8*)s,strlen(s),&e);return e.width;}
static void draw_text(const char *s,XftFont *f,int x,int y,const char *col){
    XftColor fc;xftcolor(&fc,col);XftDrawStringUtf8(xdraw,&fc,f,x,y,(FcChar8*)s,strlen(s));XftColorFree(dpy,vis,cmap,&fc);}
static void draw_text_c(const char *s,XftFont *f,int cx,int cy,const char *col){
    draw_text(s,f,cx-text_w(f,s)/2,cy+f->ascent/2,col);}

/* avatar ring via cairo */
static void draw_accent_ring_cairo(int ax,int ay,int r){
    double pi2=2.0*3.14159265358979323846;
    cairo_surface_t *xs=cairo_xlib_surface_create(dpy,buf,vis,sw,sh);
    cairo_t *cr=cairo_create(xs);
    XColor xc; XParseColor(dpy,cmap,ACCENT,&xc);
    cairo_arc(cr,(double)ax,(double)ay,(double)(r-1),0,pi2);
    cairo_set_source_rgba(cr,xc.red/65535.0,xc.green/65535.0,xc.blue/65535.0,0.9);
    cairo_set_line_width(cr,2.5); cairo_stroke(cr);
    cairo_destroy(cr); cairo_surface_destroy(xs);
}

/* fallback avatar: dark circle + red ring + large icon */
static void draw_avatar_fallback(int ax,int ay,int r){
    XSetForeground(dpy,gc,mkcolor(AVATAR_BG));
    XFillArc(dpy,buf,gc,ax-r,ay-r,r*2,r*2,0,360*64);
    draw_accent_ring_cairo(ax,ay,r);
    if (font_fa_avt) draw_text_c(FA_USER,font_fa_avt,ax,ay,ACCENT);
}

static void draw_avatar_at(int idx,int ax,int ay,int radius){
    if (idx>=0&&idx<nusers&&avatar_loaded[idx]&&avatar_surf[idx]){
        draw_cairo_circle(avatar_surf[idx],ax,ay,radius); return; }
    draw_avatar_fallback(ax,ay,radius);
}

static void draw_lock_avatar(int ax,int ay,int radius){
    for (int i=0;i<nusers;i++) if (strcmp(users[i].name,lock_user)==0){draw_avatar_at(i,ax,ay,radius);return;}
    if (!lock_avatar_done){
        lock_avatar_done=1;
        struct passwd *pw=getpwnam(lock_user);
        if (pw){
            char apath[320];
            snprintf(apath,sizeof(apath),"%s/.config/mrrobotos/mrsettings/account/avatar",pw->pw_dir);
            lock_avatar_surf=load_avatar_surface(apath,radius);
            LOG_INFO_MSG("lock avatar %s: %s",apath,lock_avatar_surf?"OK":"FAILED");
        }
    }
    if (lock_avatar_surf){draw_cairo_circle(lock_avatar_surf,ax,ay,radius);return;}
    draw_avatar_fallback(ax,ay,radius);
}

static void draw_logo(int x,int y){
    if (!logo_surf) return;
    cairo_surface_t *xs=cairo_xlib_surface_create(dpy,buf,vis,sw,sh);
    cairo_t *cr=cairo_create(xs);
    cairo_set_source_surface(cr,logo_surf,x,y); cairo_paint(cr);
    cairo_destroy(cr); cairo_surface_destroy(xs);
}

static void draw_background(void){
    XSetForeground(dpy,gc,mkcolor(BG_COLOR)); XFillRectangle(dpy,buf,gc,0,0,sw,sh);
    XSetForeground(dpy,gc,mkcolor("#0e0e10"));
    for(int gx=0;gx<sw;gx+=40) XDrawLine(dpy,buf,gc,gx,0,gx,sh);
    for(int gy=0;gy<sh;gy+=40) XDrawLine(dpy,buf,gc,0,gy,sw,gy);
    int b=3; XSetForeground(dpy,gc,mkcolor(ACCENT));
    XFillRectangle(dpy,buf,gc,0,0,sw,b); XFillRectangle(dpy,buf,gc,0,sh-b,sw,b);
    XFillRectangle(dpy,buf,gc,0,0,b,sh); XFillRectangle(dpy,buf,gc,sw-b,0,b,sh);
}

static void draw_clock(void){
    time_t t=time(NULL); struct tm *tm=localtime(&t);
    char hhmm[16],date[64];
    strftime(hhmm,sizeof(hhmm),"%H:%M",tm); strftime(date,sizeof(date),"%A, %d %B %Y",tm);
    int cx=sw/2,cy=sh/2-CARD_H/2-100;
    draw_text_c(hhmm,font_clock,cx,cy,TEXT_COLOR); draw_text_c(date,font_date,cx,cy+64,TEXT_MID);
    XSetForeground(dpy,gc,mkcolor(SEPARATOR)); XDrawLine(dpy,buf,gc,cx-120,cy+84,cx+120,cy+84);
}

static void draw_branding(void){
    int lw=logo_surf?logo_surf_w:0,lh=logo_surf?logo_surf_h:0;
    int btw=text_w(font_brand,BRAND_NAME),gap=lw>0?20:0,total=lw+gap+btw;
    int bx=sw/2-total/2,centre_y=sh-90;
    if (lw>0) draw_logo(bx,centre_y-lh/2);
    int txt_base=centre_y+font_brand->ascent/2-font_brand->descent/2;
    draw_text(BRAND_NAME,font_brand,bx+lw+gap,txt_base,TEXT_MID);
}

static void draw_card(int cx,int cy){
    XSetForeground(dpy,gc,mkcolor("#050507")); fill_rounded(cx+4,cy+4,CARD_W,CARD_H,CARD_R);
    XSetForeground(dpy,gc,mkcolor(CARD_COLOR)); fill_rounded(cx,cy,CARD_W,CARD_H,CARD_R);
    XSetForeground(dpy,gc,mkcolor(ACCENT));
    stroke_rounded(cx,cy,CARD_W,CARD_H,CARD_R); stroke_rounded(cx+1,cy+1,CARD_W-2,CARD_H-2,CARD_R-1);
}

static void draw_password_field(int x,int y,int w){
    draw_text("Password",font_label,x,y-8,TEXT_DIM);
    XSetForeground(dpy,gc,mkcolor(INPUT_FOCUS)); fill_rounded(x,y,w,INPUT_H,INPUT_R);
    XSetForeground(dpy,gc,mkcolor(ACCENT)); stroke_rounded(x,y,w,INPUT_H,INPUT_R);
    int icon_sz=INPUT_H-18; eye_w=icon_sz;eye_h=icon_sz;
    eye_x=x+w-icon_sz-14; eye_y=y+(INPUT_H-icon_sz)/2;
    if (font_fa){const char *ei=show_pass?FA_EYE_SLASH:FA_EYE;
        draw_text_c(ei,font_fa,eye_x+eye_w/2,eye_y+eye_h/2,show_pass?ACCENT:TEXT_DIM);}
    char display[512]="";
    if (show_pass){strncpy(display,pass_buf,255);display[255]=0;}
    else{for(int i=0;i<pass_len&&i<127;i++) strcat(display,"●");}
    if (cursor_visible) strcat(display,"▌");
    int line_h=font_input->ascent+font_input->descent;
    int baseline=y+INPUT_H/2+font_input->ascent-line_h/2;
    draw_text(display,font_input,x+24,baseline,TEXT_COLOR);
}

static void draw_login_button(int ix,int iw,int lby,int is_lock){
    XSetForeground(dpy,gc,mkcolor(ACCENT)); fill_rounded(ix,lby,iw,INPUT_H,INPUT_R);
    XSetForeground(dpy,gc,mkcolor(ACCENT2)); fill_rounded(ix+1,lby+1,iw-2,INPUT_H/2,INPUT_R);
    int line_h=font_title->ascent+font_title->descent;
    int base_y=lby+INPUT_H/2+font_title->ascent-line_h/2;
    const char *label=is_lock?"UNLOCK":"LOGIN";
    int lw2=text_w(font_title,label),arrow_gap=font_fa_lg?text_w(font_fa_lg,FA_ARROW)+12:0;
    int label_x=sw/2-(lw2+arrow_gap)/2;
    draw_text(label,font_title,label_x,base_y,TEXT_COLOR);
    if (font_fa_lg){int fh=font_fa_lg->ascent+font_fa_lg->descent;
        int fb=lby+INPUT_H/2+font_fa_lg->ascent-fh/2;
        draw_text(FA_ARROW,font_fa_lg,label_x+lw2+12,fb,TEXT_COLOR);}
}

static void draw_error(int ix,int iw,int eby){
    if (auth_success_shown){
        XSetForeground(dpy,gc,mkcolor("#0a2a12")); fill_rounded(ix,eby,iw,30,6);
        if(font_fa)draw_text_c(FA_CHECK,font_fa,ix+20,eby+16,SUCCESS_COLOR);
        draw_text_c("Authenticated!",font_label,sw/2+10,eby+16,SUCCESS_COLOR); return;}
    if (!error_msg[0]) return;
    XSetForeground(dpy,gc,mkcolor("#2a0a0a")); fill_rounded(ix,eby,iw,30,6);
    if(font_fa)draw_text_c(FA_WARNING,font_fa,ix+20,eby+16,ERROR_COLOR);
    draw_text_c(error_msg,font_label,sw/2+10,eby+16,ERROR_COLOR);
}

static void flush_buf(void){
    GC wgc=XCreateGC(dpy,win,0,NULL);
    XCopyArea(dpy,buf,win,wgc,0,0,sw,sh,0,0); XFreeGC(dpy,wgc); XFlush(dpy);
}

/*
 * Unified layout — same for both login and lock:
 *
 *   sep1  = cy + 56
 *   avatar_cy = sep1 + MID_GAP_TOP + AVATAR_R
 *   name_y    = avatar_cy + AVATAR_R + 12
 *   sep2  = name_y + NAME_H + MID_GAP_BOT
 *   pwd_label = sep2 + BOT_PAD_TOP              ("Password" text)
 *   py    = pwd_label + 16                      (input top)
 *   lby   = py + INPUT_H + 12                  (button top)
 */
static int card_layout(int card_y,int *avatar_cy_out,int *sep2_y_out){
    int sep1    = card_y + 56;
    int avt_cy  = sep1 + MID_GAP_TOP + AVATAR_R;
    int name_y  = avt_cy + AVATAR_R + 12;
    int sep2    = name_y + NAME_H + MID_GAP_BOT;
    int py      = sep2 + BOT_PAD_TOP + 16;
    if (avatar_cy_out) *avatar_cy_out = avt_cy;
    if (sep2_y_out)    *sep2_y_out    = sep2;
    return py;
}

static void redraw(void){
    draw_background(); draw_clock();
    int cx=sw/2-CARD_W/2, cy=sh/2-CARD_H/2;
    draw_card(cx,cy);
    draw_text_c("Welcome Back",font_title,sw/2,cy+18,TEXT_COLOR);
    draw_text_c("Sign in to your account",font_subtitle,sw/2,cy+38,TEXT_DIM);
    XSetForeground(dpy,gc,mkcolor(SEPARATOR));
    XDrawLine(dpy,buf,gc,cx+20,cy+56,cx+CARD_W-20,cy+56);

    int avt_cy,sep2;
    int py=card_layout(cy,&avt_cy,&sep2);
    int lby=py+INPUT_H+12;
    int ix=cx+24,iw=CARD_W-48;
    int name_y=avt_cy+AVATAR_R+12;

    arr_l_x=cx+16;       arr_l_y=avt_cy-ARROW_H/2;
    arr_r_x=cx+CARD_W-16-ARROW_W; arr_r_y=avt_cy-ARROW_H/2;

    if (nusers>1){
        XSetForeground(dpy,gc,mkcolor(ARROW_COLOR)); fill_rounded(arr_l_x,arr_l_y,ARROW_W,ARROW_H,8);
        if(font_fa)draw_text_c(FA_CHEVRON_L,font_fa,arr_l_x+ARROW_W/2,arr_l_y+ARROW_H/2,TEXT_MID);
        XSetForeground(dpy,gc,mkcolor(ARROW_COLOR)); fill_rounded(arr_r_x,arr_r_y,ARROW_W,ARROW_H,8);
        if(font_fa)draw_text_c(FA_CHEVRON_R,font_fa,arr_r_x+ARROW_W/2,arr_r_y+ARROW_H/2,TEXT_MID);
    }

    draw_avatar_at(sel_user,sw/2,avt_cy,AVATAR_R);
    draw_text_c(users[sel_user].name,font_user,sw/2,name_y,TEXT_COLOR);

    XSetForeground(dpy,gc,mkcolor(SEPARATOR));
    XDrawLine(dpy,buf,gc,cx+20,sep2,cx+CARD_W-20,sep2);

    draw_password_field(ix,py,iw);
    draw_login_button(ix,iw,lby,0);
    draw_error(ix,iw,lby+INPUT_H+8);

    const char *hint=nusers>1
        ?"\xe2\x86\x90 \xe2\x86\x92 Switch User    Enter \xc2\xb7 Login    Esc \xc2\xb7 Clear"
        :"Enter \xc2\xb7 Login    Esc \xc2\xb7 Clear";
    draw_text_c(hint,font_label,sw/2,cy+CARD_H+18,TEXT_DIM);
    draw_branding(); flush_buf();
}

static void draw_lock_screen(void){
    draw_background(); draw_clock();
    int cx=sw/2-CARD_W/2, cy=sh/2-CARD_H/2;
    draw_card(cx,cy);
    draw_text_c("Screen Locked",font_title,sw/2,cy+18,TEXT_COLOR);
    draw_text_c("Enter your password to unlock",font_subtitle,sw/2,cy+38,TEXT_DIM);
    XSetForeground(dpy,gc,mkcolor(SEPARATOR));
    XDrawLine(dpy,buf,gc,cx+20,cy+56,cx+CARD_W-20,cy+56);

    int avt_cy,sep2;
    int py=card_layout(cy,&avt_cy,&sep2);
    int lby=py+INPUT_H+12;
    int ix=cx+24,iw=CARD_W-48;
    int name_y=avt_cy+AVATAR_R+12;

    draw_lock_avatar(sw/2,avt_cy,AVATAR_R);
    if(font_fa)draw_text_c(FA_LOCK,font_fa,sw/2+AVATAR_R-8,avt_cy+AVATAR_R-8,ACCENT);
    draw_text_c(lock_user,font_user,sw/2,name_y,TEXT_COLOR);

    XSetForeground(dpy,gc,mkcolor(SEPARATOR));
    XDrawLine(dpy,buf,gc,cx+20,sep2,cx+CARD_W-20,sep2);

    draw_password_field(ix,py,iw);
    draw_login_button(ix,iw,lby,1);
    draw_error(ix,iw,lby+INPUT_H+8);
    draw_text_c("Enter \xc2\xb7 Unlock    Esc \xc2\xb7 Clear",font_label,sw/2,cy+CARD_H+18,TEXT_DIM);
    draw_branding(); flush_buf();
}

static void do_redraw(void){if(lock_mode)draw_lock_screen();else redraw();}

static void try_login(void){
    if (!pass_len){strcpy(error_msg,"Please enter your password");do_redraw();return;}
    strcpy(error_msg,"Authenticating..."); do_redraw();
    const char *uname=lock_mode?lock_user:users[sel_user].name;
    if (authenticate(uname,pass_buf)){
        auth_success_shown=1;fail_count=0;strcpy(error_msg,"");
        do_redraw();
        struct timeval tv={0,400000}; select(0,NULL,NULL,NULL,&tv);
        auth_ok=1;
    } else {
        fail_count++; strcpy(error_msg,"Incorrect password.");
        memset(pass_buf,0,sizeof(pass_buf)); pass_len=0; do_redraw();
    }
}

static void start_session(void){
    UserInfo *u=&users[sel_user];
    if (u->uid!=0){
        char new_xauth[300];
        snprintf(new_xauth,sizeof(new_xauth),"%s/.Xauthority",u->home);
        char xauth_cmd[512];
        snprintf(xauth_cmd,sizeof(xauth_cmd),
                 "xauth -f /tmp/.mrlogin.xauth extract - :0 | xauth -f %s merge -",new_xauth);
        system(xauth_cmd);
        chown(new_xauth,u->uid,u->gid); chmod(new_xauth,0600);
        char xdg_runtime[64]; snprintf(xdg_runtime,sizeof(xdg_runtime),"/run/user/%d",u->uid);
        mkdir(xdg_runtime,0700); chown(xdg_runtime,u->uid,u->gid); chmod(xdg_runtime,0700);
        if(initgroups(u->name,u->gid)!=0)LOG_ERR_MSG("initgroups: %s",strerror(errno));
        if(setgid(u->gid)!=0)LOG_ERR_MSG("setgid: %s",strerror(errno));
        if(setuid(u->uid)!=0){LOG_ERR_MSG("setuid: %s",strerror(errno));exit(1);}
        if(getuid()==0||getgid()==0){LOG_ERR_MSG("failed to drop root");exit(1);}
        setenv("XAUTHORITY",new_xauth,1);
	setenv("XDG_RUNTIME_DIR",xdg_runtime,1);
    } else {
        char *xa=getenv("XAUTHORITY");
        if(!xa||!*xa)setenv("XAUTHORITY","/tmp/.mrlogin.xauth",1);
        mkdir("/run/user/0",0700);
	setenv("XDG_RUNTIME_DIR","/run/user/0",1);
    }
    setenv("HOME",u->home,1);
    setenv("USER",u->name,1);
    setenv("LOGNAME",u->name,1);
    setenv("SHELL",u->shell,1);
    setenv("NO_AT_BRIDGE","1",1);
    char *disp = getenv("DISPLAY");
    setenv("DISPLAY",disp?disp:":0",1);
    char path[512];
    snprintf(path,sizeof(path),
             "/usr/bin:/usr/local/bin:/usr/local/sbin:/bin:"
             "/usr/local/bin/mrblocks:"
             "/usr/local/bin/mrpanel:"
             "/usr/local/bin/system-scripts");
    setenv("PATH",path,1);

    char zdotdir[512];
    snprintf(zdotdir,sizeof(zdotdir),"%s/.config/zsh",u->home);
    setenv("ZDOTDIR",zdotdir,1);

    char xdg_config[512],xdg_data[512],xdg_cache[512],
	 xdg_state[512],xdg_source[512], xdg_binary[512];
    snprintf(xdg_config,sizeof(xdg_config),"%s/.config",u->home);
    snprintf(xdg_data,  sizeof(xdg_data),  "%s/.local/share",u->home);
    snprintf(xdg_cache, sizeof(xdg_cache), "%s/.cache",u->home);
    snprintf(xdg_state, sizeof(xdg_state), "%s/.local/state",  u->home);
    snprintf(xdg_source, sizeof(xdg_source), "%s/.local/src", u->home);
    snprintf(xdg_binary, sizeof(xdg_binary), "%s/.local/bin", u->home);

    setenv("XDG_CONFIG_HOME",xdg_config,1);
    setenv("XDG_DATA_HOME",xdg_data,1);
    setenv("XDG_CACHE_HOME",xdg_cache,1);
    setenv("XDG_STATE_HOME",  xdg_state,  1);
    setenv("XDG_SOURCE_HOME", xdg_source, 1);
    setenv("XDG_BINARY_HOME", xdg_binary, 1);

    if(chdir(u->home)!=0)LOG_ERR_MSG("chdir: %s",strerror(errno));
    char xinitrc[300]; snprintf(xinitrc,sizeof(xinitrc),"%s/.xinitrc",u->home);
    if(access(xinitrc,X_OK)==0){
        execl("/bin/zsh","zsh",xinitrc,NULL);
        execl("/bin/sh","sh",xinitrc,NULL);
    } else {
        execl("/usr/bin/dbus-run-session","dbus-run-session","/usr/bin/mrdwm",NULL);
        execl("/usr/bin/mrdwm","mrdwm",NULL);
    }
    LOG_ERR_MSG("execl: %s",strerror(errno)); exit(1);
}

static int login_btn_top_y(void){
    int cy=sh/2-CARD_H/2;
    int py=card_layout(cy,NULL,NULL);
    return py+INPUT_H+12;
}

int main(int argc,char *argv[]){
    openlog("mrlogin",LOG_PID|LOG_CONS,LOG_AUTH);
    for (int i=1;i<argc;i++){
        if(strcmp(argv[i],"--lock")==0){
            lock_mode=1;
            struct passwd *pw=getpwuid(getuid());
            if(pw)strncpy(lock_user,pw->pw_name,63);
        } else if(strcmp(argv[i],"--root")==0){
            root_mode=1;
        }
    }
    setenv("DISPLAY",":0",0); setenv("XAUTHORITY","/tmp/.mrlogin.xauth",0);
    dpy=XOpenDisplay(getenv("DISPLAY"));
    if(!dpy){LOG_ERR_MSG("cannot open display");closelog();return 1;}
    screen=DefaultScreen(dpy); root_win=RootWindow(dpy,screen);
    vis=DefaultVisual(dpy,screen); cmap=DefaultColormap(dpy,screen);
    has_scrnsaver=XScreenSaverQueryExtension(dpy,&ss_event_base,&ss_error_base);
    if(!has_scrnsaver)LOG_WARN_MSG("XScreenSaver ext not available");
    get_primary_monitor(); get_users();
    if(nusers==0){LOG_ERR_MSG("no users found");closelog();return 1;}
    load_avatars(); load_logo();
    if(lock_mode&&lock_user[0])
        for(int i=0;i<nusers;i++)
            if(strcmp(users[i].name,lock_user)==0){sel_user=i;break;}
    XSetWindowAttributes wa;
    wa.override_redirect=True; wa.background_pixel=mkcolor(BG_COLOR);
    wa.event_mask=KeyPressMask|ButtonPressMask|ButtonReleaseMask|PointerMotionMask|ExposureMask;
    win=XCreateWindow(dpy,root_win,0,0,sw,sh,0,DefaultDepth(dpy,screen),InputOutput,vis,
                      CWOverrideRedirect|CWBackPixel|CWEventMask,&wa);
    XMapRaised(dpy,win);
    XGrabKeyboard(dpy,win,True,GrabModeAsync,GrabModeAsync,CurrentTime);
    XGrabPointer(dpy,win,True,ButtonPressMask|ButtonReleaseMask|PointerMotionMask,
                 GrabModeAsync,GrabModeAsync,win,None,CurrentTime);
    buf=XCreatePixmap(dpy,root_win,sw,sh,DefaultDepth(dpy,screen));
    gc=XCreateGC(dpy,buf,0,NULL); xdraw=XftDrawCreate(dpy,buf,vis,cmap);
    font_title   =XftFontOpenName(dpy,screen,FONT_TITLE);
    font_subtitle=XftFontOpenName(dpy,screen,FONT_SUBTITLE);
    font_input   =XftFontOpenName(dpy,screen,FONT_INPUT);
    font_label   =XftFontOpenName(dpy,screen,FONT_LABEL);
    font_clock   =XftFontOpenName(dpy,screen,FONT_CLOCK);
    font_date    =XftFontOpenName(dpy,screen,FONT_DATE);
    font_user    =XftFontOpenName(dpy,screen,FONT_USER);
    font_brand   =XftFontOpenName(dpy,screen,FONT_BRAND);
    font_fa      =XftFontOpenName(dpy,screen,FONT_FA);
    font_fa_lg   =XftFontOpenName(dpy,screen,FONT_FA_LG);
    font_fa_avt  =XftFontOpenName(dpy,screen,FONT_FA_AVT);
    if(!font_title||!font_input||!font_clock||!font_date||
       !font_label||!font_user||!font_subtitle||!font_brand){
        LOG_ERR_MSG("failed to load required fonts");closelog();return 1;}
    if(!font_fa||!font_fa_lg)LOG_WARN_MSG("Font Awesome not found");
    Cursor cursor_normal=XCreateFontCursor(dpy,68);
    Cursor cursor_hand  =XCreateFontCursor(dpy,60);
    XDefineCursor(dpy,win,cursor_normal);
    do_redraw();
    LOG_INFO_MSG("started in %s mode",lock_mode?"lock":(root_mode?"root":"login"));
    XEvent ev;
    time_t last_clock=0,last_idle_check=0;
    struct timeval last_blink_tv; gettimeofday(&last_blink_tv,NULL);
    while (!auth_ok){
        struct timeval tv={0,100000};
        int fd=ConnectionNumber(dpy); fd_set fds; FD_ZERO(&fds); FD_SET(fd,&fds);
        select(fd+1,&fds,NULL,NULL,&tv);
        struct timeval now_tv; gettimeofday(&now_tv,NULL);
        long elapsed_ms=(now_tv.tv_sec-last_blink_tv.tv_sec)*1000+
                        (now_tv.tv_usec-last_blink_tv.tv_usec)/1000;
        if(elapsed_ms>=CURSOR_BLINK_MS){cursor_visible=!cursor_visible;last_blink_tv=now_tv;do_redraw();}
        time_t now=time(NULL);
        if(now!=last_clock){last_clock=now;do_redraw();}
        if(!lock_mode&&!root_mode&&has_scrnsaver&&(now-last_idle_check)>=(IDLE_CHECK_MS/1000)){
            last_idle_check=now;
            if(get_idle_ms()>=(unsigned long)(IDLE_TIMEOUT_SEC*1000)){
                LOG_INFO_MSG("idle timeout, locking"); lock_mode=1;
                if(sel_user>=0&&sel_user<nusers)strncpy(lock_user,users[sel_user].name,63);
                memset(pass_buf,0,sizeof(pass_buf)); pass_len=0; error_msg[0]='\0'; do_redraw();
            }
        }
        while (XPending(dpy)){
            XNextEvent(dpy,&ev);
            if(ev.type==Expose){do_redraw();}
            else if(ev.type==ButtonPress){
                int bx=ev.xbutton.x,by=ev.xbutton.y;
                int cx=sw/2-CARD_W/2,ix=cx+24,iw=CARD_W-48,lby=login_btn_top_y();
                if(eye_w>0&&bx>=eye_x&&bx<=eye_x+eye_w&&by>=eye_y&&by<=eye_y+eye_h)
                    {show_pass=!show_pass;do_redraw();continue;}
                if(bx>=ix&&bx<=ix+iw&&by>=lby&&by<=lby+INPUT_H){try_login();continue;}
                if(!lock_mode&&nusers>1){
                    if(bx>=arr_l_x&&bx<=arr_l_x+ARROW_W&&by>=arr_l_y&&by<=arr_l_y+ARROW_H)
                        {sel_user=(sel_user-1+nusers)%nusers;memset(pass_buf,0,sizeof(pass_buf));
                         pass_len=0;error_msg[0]='\0';fail_count=0;do_redraw();continue;}
                    if(bx>=arr_r_x&&bx<=arr_r_x+ARROW_W&&by>=arr_r_y&&by<=arr_r_y+ARROW_H)
                        {sel_user=(sel_user+1)%nusers;memset(pass_buf,0,sizeof(pass_buf));
                         pass_len=0;error_msg[0]='\0';fail_count=0;do_redraw();continue;}
                }
                do_redraw();
            }
            else if(ev.type==ButtonRelease){do_redraw();}
            else if(ev.type==MotionNotify){
                int mx=ev.xmotion.x,my=ev.xmotion.y;
                int cx=sw/2-CARD_W/2,ix=cx+24,iw=CARD_W-48,lby=login_btn_top_y();
                int hovering=0;
                if(mx>=ix&&mx<=ix+iw&&my>=lby&&my<=lby+INPUT_H)hovering=1;
                if(!hovering&&eye_w>0&&mx>=eye_x&&mx<=eye_x+eye_w&&my>=eye_y&&my<=eye_y+eye_h)hovering=1;
                if(!lock_mode&&!hovering&&nusers>1){
                    if((mx>=arr_l_x&&mx<=arr_l_x+ARROW_W&&my>=arr_l_y&&my<=arr_l_y+ARROW_H)||
                       (mx>=arr_r_x&&mx<=arr_r_x+ARROW_W&&my>=arr_r_y&&my<=arr_r_y+ARROW_H))hovering=1;
                }
                XDefineCursor(dpy,win,hovering?cursor_hand:cursor_normal);
            }
            else if(ev.type==KeyPress){
                cursor_visible=1; gettimeofday(&last_blink_tv,NULL);
                char kbuf[32]={0}; KeySym ks;
                XLookupString(&ev.xkey,kbuf,sizeof(kbuf),&ks,NULL);
                if(ks==XK_Return||ks==XK_KP_Enter){try_login();}
                else if((ks==XK_Tab||ks==XK_Right)&&!lock_mode&&nusers>1)
                    {sel_user=(sel_user+1)%nusers;memset(pass_buf,0,sizeof(pass_buf));
                     pass_len=0;error_msg[0]='\0';fail_count=0;do_redraw();}
                else if(ks==XK_Left&&!lock_mode&&nusers>1)
                    {sel_user=(sel_user-1+nusers)%nusers;memset(pass_buf,0,sizeof(pass_buf));
                     pass_len=0;error_msg[0]='\0';fail_count=0;do_redraw();}
                else if(ks==XK_BackSpace){if(pass_len>0)pass_buf[--pass_len]='\0';do_redraw();}
                else if(ks==XK_Escape){memset(pass_buf,0,sizeof(pass_buf));pass_len=0;error_msg[0]='\0';show_pass=0;do_redraw();}
                else if(kbuf[0]>=32&&kbuf[0]<127){if(pass_len<255)pass_buf[pass_len++]=kbuf[0];do_redraw();}
            }
        }
    }
    for(int i=0;i<nusers;i++)if(avatar_surf[i])cairo_surface_destroy(avatar_surf[i]);
    if(lock_avatar_surf)cairo_surface_destroy(lock_avatar_surf);
    if(logo_surf)cairo_surface_destroy(logo_surf);
    XftDrawDestroy(xdraw); XFreePixmap(dpy,buf);
    XFreeCursor(dpy,cursor_normal); XFreeCursor(dpy,cursor_hand);
    XUngrabKeyboard(dpy,CurrentTime); XUngrabPointer(dpy,CurrentTime);
    XDestroyWindow(dpy,win); XCloseDisplay(dpy);
    if(lock_mode){
        if(global_pamh){pam_close_session(global_pamh,0);pam_end(global_pamh,PAM_SUCCESS);}
        LOG_INFO_MSG("screen unlocked for %s",lock_user); closelog(); return 0;
    }
    pid_t pid=fork();
    if(pid==0){start_session();exit(1);}
    else if(pid>0){
        int status;waitpid(pid,&status,0);
        if(global_pamh){pam_close_session(global_pamh,0);pam_end(global_pamh,PAM_SUCCESS);global_pamh=NULL;}
        LOG_INFO_MSG("session ended for %s",users[sel_user].name);
    } else {
        LOG_ERR_MSG("fork: %s",strerror(errno));
        if(global_pamh){pam_close_session(global_pamh,0);pam_end(global_pamh,PAM_SUCCESS);}
        closelog();return 1;
    }
    closelog(); return 0;
}
