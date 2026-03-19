/* MrLogin - Display Manager for MrRobotOS
 * Compile: gcc -o mrlogin mrlogin.c -lX11 -lXft -lpam -I/usr/include/freetype2
 * Maintainer: Bora Poçan - mborapocan@gmail.com
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
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
#include <security/pam_appl.h>

/* appearance */
#define CARD_W        500
#define CARD_H        580
#define CARD_R        20
#define INPUT_H       52
#define INPUT_R       10
#define USER_BTN_W    130
#define USER_BTN_H    100
#define USER_BTN_R    14
#define AVATAR_R      28
#define DOT_PAD_Y     14  /* padding above and below dots */
#define BG_COLOR      "#0a0a0c"
#define CARD_COLOR    "#161618"
#define INPUT_FOCUS   "#2a2a2c"
#define ACCENT        "#e63946"
#define ACCENT2       "#c1121f"
#define TEXT_COLOR    "#f0f0f0"
#define TEXT_DIM      "#6e6e73"
#define TEXT_MID      "#aeaeb2"
#define ERROR_COLOR   "#ff453a"
#define WARN_COLOR    "#ff9f0a"
#define USER_SEL      "#e63946"
#define USER_NORM     "#1e1e20"
#define SEPARATOR     "#2c2c2e"
#define FONT_TITLE    "monospace:size=18:bold"
#define FONT_SUBTITLE "monospace:size=11"
#define FONT_INPUT    "monospace:size=14"
#define FONT_LABEL    "monospace:size=10"
#define FONT_CLOCK    "monospace:size=52:bold"
#define FONT_DATE     "monospace:size=13"
#define FONT_USER     "monospace:size=11"
#define FONT_AVATAR   "monospace:size=16:bold"
#define FONT_FA       "Font Awesome 7 Free Solid:size=16"
#define FONT_FA_LG    "Font Awesome 7 Free Solid:size=20"
#define MIN_UID       1000
#define MAX_USERS     8
#define MAX_ATTEMPTS  5
#define LOCK_TIMES_COUNT 5

static int lock_durations[] = { 60, 300, 900, 3600, -1 };

typedef struct {
	char name[64];
	char home[256];
	char shell[256];
	uid_t uid;
	gid_t gid;
} UserInfo;

static UserInfo users[MAX_USERS];
static int      nusers     = 0;
static int      sel_user   = 0;
static int      show_pass  = 0;
static int      fail_count = 0;
static int      lock_level = 0;
static time_t   locked_until = 0;
static int      disabled   = 0;

static Display *dpy;
static Window   root, win;
static int      screen;
static GC       gc;
static XftDraw *xdraw;
static XftFont *font_title, *font_subtitle, *font_input, *font_label;
static XftFont *font_clock, *font_date, *font_user, *font_avatar;
static XftFont *font_fa, *font_fa_lg;
static Colormap cmap;
static Visual  *vis;
static int      sw, sh;

static char pass_buf[256] = "";
static int  pass_len      = 0;
static char error_msg[128]= "";
static int  auth_ok       = 0;

static int eye_x = 0, eye_y = 0, eye_w = 36, eye_h = 36;

#define FA_EYE       "\xef\x80\xae"
#define FA_EYE_SLASH "\xef\x81\xb0"
#define FA_LOCK      "\xef\x80\xa3"
#define FA_ARROW     "\xef\x81\xa1"
#define FA_USER      "\xef\x80\x87"
#define FA_WARNING   "\xef\x81\xb1"

static const char *pam_password = NULL;
static int pam_conv_func(int num_msg, const struct pam_message **msg,
                         struct pam_response **resp, void *appdata) {
	*resp = calloc(num_msg, sizeof(struct pam_response));
	for (int i = 0; i < num_msg; i++)
		if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF ||
		    msg[i]->msg_style == PAM_PROMPT_ECHO_ON)
			(*resp)[i].resp = strdup(pam_password ? pam_password : "");
	return PAM_SUCCESS;
}

static int authenticate(const char *user, const char *pass) {
	pam_password = pass;
	struct pam_conv conv = { pam_conv_func, NULL };
	pam_handle_t *pamh = NULL;
	int ret = pam_start("login", user, &conv, &pamh);
	if (ret == PAM_SUCCESS) ret = pam_authenticate(pamh, 0);
	if (ret == PAM_SUCCESS) ret = pam_acct_mgmt(pamh, 0);
	pam_end(pamh, ret);
	return ret == PAM_SUCCESS;
}

static void get_users(void) {
	struct passwd *pw;
	setpwent();
	while ((pw = getpwent()) && nusers < MAX_USERS) {
		if (pw->pw_uid < MIN_UID) continue;
		if (strcmp(pw->pw_name, "nobody") == 0) continue;
		if (strcmp(pw->pw_shell, "/sbin/nologin") == 0) continue;
		if (strcmp(pw->pw_shell, "/bin/false") == 0) continue;
		if (strcmp(pw->pw_shell, "/usr/bin/nologin") == 0) continue;
		struct stat st;
		if (stat(pw->pw_dir, &st) != 0) continue;
		strncpy(users[nusers].name,  pw->pw_name,  63);
		strncpy(users[nusers].home,  pw->pw_dir,   255);
		strncpy(users[nusers].shell, pw->pw_shell, 255);
		users[nusers].uid = pw->pw_uid;
		users[nusers].gid = pw->pw_gid;
		nusers++;
	}
	endpwent();
}

static void get_primary_monitor(void) {
	sw = DisplayWidth(dpy, screen);
	sh = DisplayHeight(dpy, screen);
	FILE *f = popen("xrandr | grep ' connected primary' | grep -o '[0-9]*x[0-9]*+[0-9]*+[0-9]*'", "r");
	if (!f) return;
	int w, h, x, y;
	if (fscanf(f, "%dx%d+%d+%d", &w, &h, &x, &y) == 4) {
		sw = w; sh = h;
	}
	pclose(f);
}

static unsigned long mkcolor(const char *hex) {
	XColor c;
	XParseColor(dpy, cmap, hex, &c);
	XAllocColor(dpy, cmap, &c);
	return c.pixel;
}

static void xftcolor(XftColor *out, const char *hex) {
	XftColorAllocName(dpy, vis, cmap, hex, out);
}

static void fill_rounded(int x, int y, int w, int h, int r) {
	if (r < 1) { XFillRectangle(dpy, win, gc, x, y, w, h); return; }
	XFillRectangle(dpy, win, gc, x+r, y, w-2*r, h);
	XFillRectangle(dpy, win, gc, x, y+r, w, h-2*r);
	XFillArc(dpy, win, gc, x,       y,       2*r, 2*r, 90*64,  90*64);
	XFillArc(dpy, win, gc, x+w-2*r, y,       2*r, 2*r, 0,      90*64);
	XFillArc(dpy, win, gc, x,       y+h-2*r, 2*r, 2*r, 180*64, 90*64);
	XFillArc(dpy, win, gc, x+w-2*r, y+h-2*r, 2*r, 2*r, 270*64, 90*64);
}

static void stroke_rounded(int x, int y, int w, int h, int r) {
	XDrawArc(dpy, win, gc, x,       y,       2*r, 2*r, 90*64,  90*64);
	XDrawArc(dpy, win, gc, x+w-2*r, y,       2*r, 2*r, 0,      90*64);
	XDrawArc(dpy, win, gc, x,       y+h-2*r, 2*r, 2*r, 180*64, 90*64);
	XDrawArc(dpy, win, gc, x+w-2*r, y+h-2*r, 2*r, 2*r, 270*64, 90*64);
	XDrawLine(dpy, win, gc, x+r, y,   x+w-r, y);
	XDrawLine(dpy, win, gc, x+r, y+h, x+w-r, y+h);
	XDrawLine(dpy, win, gc, x,   y+r, x,     y+h-r);
	XDrawLine(dpy, win, gc, x+w, y+r, x+w,   y+h-r);
}

static int text_w(XftFont *f, const char *s) {
	XGlyphInfo e;
	XftTextExtentsUtf8(dpy, f, (FcChar8*)s, strlen(s), &e);
	return e.width;
}

static void draw_text(const char *s, XftFont *f, int x, int y, const char *col) {
	XftColor fc;
	xftcolor(&fc, col);
	XftDrawStringUtf8(xdraw, &fc, f, x, y, (FcChar8*)s, strlen(s));
	XftColorFree(dpy, vis, cmap, &fc);
}

static void draw_text_c(const char *s, XftFont *f, int cx, int cy, const char *col) {
	draw_text(s, f, cx - text_w(f, s)/2, cy + f->ascent/2, col);
}

static void draw_clock(void) {
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	char full_time[32], date[64];
	strftime(full_time, sizeof(full_time), "%H:%M:%S", tm);
	strftime(date,      sizeof(date),      "%A, %d %B %Y", tm);
	int cx = sw/2;
	int cy = sh/2 - CARD_H/2 - 100;
	draw_text_c(full_time, font_clock, cx, cy, TEXT_COLOR);
	draw_text_c(date, font_date, cx, cy + 58, TEXT_MID);
	XSetForeground(dpy, gc, mkcolor(SEPARATOR));
	XDrawLine(dpy, win, gc, cx-120, cy+78, cx+120, cy+78);
}

static void draw_users(int card_x, int card_y) {
	int cols = (nusers > 3) ? 3 : nusers;
	if (cols < 1) cols = 1;
	int gap = 12;
	int total_w = cols * USER_BTN_W + (cols-1) * gap;
	int start_x = card_x + CARD_W/2 - total_w/2;
	int uy = card_y + 80;
	for (int i = 0; i < nusers; i++) {
		int col = i % cols;
		int row = i / cols;
		int bx  = start_x + col * (USER_BTN_W + gap);
		int by  = uy + row * (USER_BTN_H + gap);
		int sel = (i == sel_user);
		XSetForeground(dpy, gc, mkcolor(sel ? USER_SEL : USER_NORM));
		fill_rounded(bx, by, USER_BTN_W, USER_BTN_H, USER_BTN_R);
		if (!sel) {
			XSetForeground(dpy, gc, mkcolor(SEPARATOR));
			stroke_rounded(bx, by, USER_BTN_W, USER_BTN_H, USER_BTN_R);
		}
		int ax = bx + USER_BTN_W/2;
		int ay = by + AVATAR_R + 12;
		XSetForeground(dpy, gc, mkcolor(sel ? ACCENT2 : "#333335"));
		XFillArc(dpy, win, gc, ax-AVATAR_R, ay-AVATAR_R, AVATAR_R*2, AVATAR_R*2, 0, 360*64);
		draw_text_c(FA_USER, font_fa, ax, ay, TEXT_COLOR);
		draw_text_c(users[i].name, font_user, bx+USER_BTN_W/2, by+USER_BTN_H-16, TEXT_COLOR);
	}
}

/* returns total height of dots section including padding */
static int dots_height(void) {
	return DOT_PAD_Y + 10 + DOT_PAD_Y; /* pad + dot diameter + pad */
}

static void draw_attempt_dots(int cx, int y) {
	/* y is top of the dots section including top padding */
	int dot_r   = 5;
	int dot_gap = 18;
	int total   = MAX_ATTEMPTS * dot_gap;
	int sx      = cx - total/2;
	int dot_cy  = y + DOT_PAD_Y + dot_r; /* center of dots with top padding */
	for (int i = 0; i < MAX_ATTEMPTS; i++) {
		int dx = sx + i * dot_gap;
		if (i < fail_count) {
			XSetForeground(dpy, gc, mkcolor(ERROR_COLOR));
			XFillArc(dpy, win, gc, dx-dot_r, dot_cy-dot_r, dot_r*2, dot_r*2, 0, 360*64);
		} else {
			XSetForeground(dpy, gc, mkcolor(SEPARATOR));
			XDrawArc(dpy, win, gc, dx-dot_r, dot_cy-dot_r, dot_r*2, dot_r*2, 0, 360*64);
		}
	}
}

static void draw_password_field(int x, int y, int w) {
	draw_text("Password", font_label, x, y - 8, TEXT_DIM);
	XSetForeground(dpy, gc, mkcolor(INPUT_FOCUS));
	fill_rounded(x, y, w, INPUT_H, INPUT_R);
	XSetForeground(dpy, gc, mkcolor(ACCENT));
	stroke_rounded(x, y, w, INPUT_H, INPUT_R);
	char display[512] = "";
	if (show_pass) {
		strncpy(display, pass_buf, sizeof(display)-2);
	} else {
		for (int i = 0; i < pass_len && i < 127; i++)
			strcat(display, "●");
	}
	strcat(display, "|");
	draw_text(display, font_input, x+16, y+INPUT_H/2+font_input->ascent/2-2, TEXT_COLOR);
	eye_x = x + w - eye_w - 12;
	eye_y = y + INPUT_H/2 - eye_h/2;
	const char *eye_icon = show_pass ? FA_EYE_SLASH : FA_EYE;
	draw_text_c(eye_icon, font_fa, eye_x+eye_w/2, eye_y+eye_h/2,
		show_pass ? ACCENT : TEXT_DIM);
}

static void draw_lockout(int x, int y, int w) {
	time_t now = time(NULL);
	if (disabled) {
		XSetForeground(dpy, gc, mkcolor("#1a0a0a"));
		fill_rounded(x, y, w, 60, 8);
		draw_text_c(FA_LOCK, font_fa_lg, x+w/2, y+20, ERROR_COLOR);
		draw_text_c("Device Disabled", font_label, x+w/2, y+44, ERROR_COLOR);
		return;
	}
	int remaining = (int)(locked_until - now);
	if (remaining > 0) {
		XSetForeground(dpy, gc, mkcolor("#1a1000"));
		fill_rounded(x, y, w, 70, 8);
		draw_text_c(FA_LOCK, font_fa_lg, x+w/2, y+22, WARN_COLOR);
		char msg[128];
		if (remaining >= 3600)
			snprintf(msg, sizeof(msg), "Try again in %dh %dm", remaining/3600, (remaining%3600)/60);
		else if (remaining >= 60)
			snprintf(msg, sizeof(msg), "Try again in %dm %ds", remaining/60, remaining%60);
		else
			snprintf(msg, sizeof(msg), "Try again in %d seconds", remaining);
		draw_text_c(msg, font_label, x+w/2, y+46, WARN_COLOR);
		char attempts[64];
		snprintf(attempts, sizeof(attempts), "%d failed attempts", fail_count);
		draw_text_c(attempts, font_label, x+w/2, y+62, TEXT_DIM);
	}
}

static void redraw(void) {
	XSetForeground(dpy, gc, mkcolor(BG_COLOR));
	XFillRectangle(dpy, win, gc, 0, 0, sw, sh);

	/* grid */
	XSetForeground(dpy, gc, mkcolor("#0e0e10"));
	for (int gx = 0; gx < sw; gx += 40)
		XDrawLine(dpy, win, gc, gx, 0, gx, sh);
	for (int gy = 0; gy < sh; gy += 40)
		XDrawLine(dpy, win, gc, 0, gy, sw, gy);

	/* top accent */
	XSetForeground(dpy, gc, mkcolor(ACCENT));
	XFillRectangle(dpy, win, gc, 0, 0, sw, 4);

	draw_clock();

	int cx = sw/2 - CARD_W/2;
	int cy = sh/2 - CARD_H/2;

	/* shadow */
	XSetForeground(dpy, gc, mkcolor("#050507"));
	fill_rounded(cx+5, cy+5, CARD_W, CARD_H, CARD_R);

	XSetForeground(dpy, gc, mkcolor(CARD_COLOR));
	fill_rounded(cx, cy, CARD_W, CARD_H, CARD_R);
	XSetForeground(dpy, gc, mkcolor(SEPARATOR));
	stroke_rounded(cx, cy, CARD_W, CARD_H, CARD_R);
	XSetForeground(dpy, gc, mkcolor(ACCENT));
	XFillRectangle(dpy, win, gc, cx+CARD_R, cy, CARD_W-2*CARD_R, 3);

	draw_text_c("Welcome Back", font_title, sw/2, cy+34, TEXT_COLOR);
	draw_text_c("Sign in to your account", font_subtitle, sw/2, cy+56, TEXT_DIM);
	XSetForeground(dpy, gc, mkcolor(SEPARATOR));
	XDrawLine(dpy, win, gc, cx+20, cy+72, cx+CARD_W-20, cy+72);

	draw_users(cx, cy);

	char welcome[128];
	snprintf(welcome, sizeof(welcome), "Signing in as  %s", users[sel_user].name);
	draw_text_c(welcome, font_label, sw/2, cy+202, TEXT_MID);

	int ix  = cx + 28;
	int iw  = CARD_W - 56;
	int py  = cy + 218;

	time_t now = time(NULL);
	int locked = !disabled && locked_until > now;

	if (disabled || locked) {
		draw_lockout(ix, py, iw);
	} else {
		draw_password_field(ix, py, iw);

		/* dots with padding */
		int dots_y = py + INPUT_H; /* top of dots section */
		draw_attempt_dots(sw/2, dots_y);

		/* login button below dots (dots section = DOT_PAD_Y + dot + DOT_PAD_Y) */
		int lby = dots_y + dots_height() + 4;
		XSetForeground(dpy, gc, mkcolor(ACCENT));
		fill_rounded(ix, lby, iw, 50, INPUT_R);
		XSetForeground(dpy, gc, mkcolor(ACCENT2));
		fill_rounded(ix+1, lby+1, iw-2, 25, INPUT_R);
		draw_text_c("LOGIN", font_title, sw/2-20, lby+26, TEXT_COLOR);
		draw_text_c(FA_ARROW, font_fa_lg, sw/2+60, lby+26, TEXT_COLOR);

		/* error */
		if (error_msg[0]) {
			int eby = lby + 58;
			XSetForeground(dpy, gc, mkcolor("#2a0a0a"));
			fill_rounded(ix, eby, iw, 30, 6);
			draw_text_c(FA_WARNING, font_fa, ix+20, eby+16, ERROR_COLOR);
			draw_text_c(error_msg, font_label, sw/2+10, eby+16, ERROR_COLOR);
		}
	}

	draw_text_c("Tab · Switch User    Enter · Login    Esc · Clear",
		font_label, sw/2, sh-18, TEXT_DIM);

	XFlush(dpy);
}

static void handle_lockout(void) {
	time_t now = time(NULL);
	if (fail_count >= MAX_ATTEMPTS) {
		if (lock_level >= LOCK_TIMES_COUNT - 1) { disabled = 1; return; }
		int duration = lock_durations[lock_level];
		if (duration < 0) { disabled = 1; return; }
		locked_until = now + duration;
		lock_level++;
		fail_count = 0;
	}
}

static void try_login(void) {
	time_t now = time(NULL);
	if (disabled) { strcpy(error_msg, "Device disabled"); return; }
	if (locked_until > now) return;
	if (!pass_len) { strcpy(error_msg, "Please enter your password"); redraw(); return; }
	strcpy(error_msg, "Authenticating...");
	redraw();
	if (authenticate(users[sel_user].name, pass_buf)) {
		auth_ok = 1;
		fail_count = 0;
		lock_level = 0;
	} else {
		fail_count++;
		handle_lockout();
		if (disabled)
			strcpy(error_msg, "Device disabled");
		else if (locked_until > now)
			strcpy(error_msg, "");
		else {
			int left = MAX_ATTEMPTS - fail_count;
			if (left > 0)
				snprintf(error_msg, sizeof(error_msg),
					"Incorrect password. %d attempt%s remaining.", left, left==1?"":"s");
			else
				snprintf(error_msg, sizeof(error_msg), "Incorrect password.");
		}
		memset(pass_buf, 0, sizeof(pass_buf));
		pass_len = 0;
	}
}

static void start_session(void) {
	UserInfo *u = &users[sel_user];
	setuid(u->uid);
	setgid(u->gid);
	initgroups(u->name, u->gid);
	setenv("HOME",    u->home,  1);
	setenv("USER",    u->name,  1);
	setenv("LOGNAME", u->name,  1);
	setenv("SHELL",   u->shell, 1);
	setenv("DISPLAY", ":0",     1);
	char zdotdir[300];
	snprintf(zdotdir, sizeof(zdotdir), "%s/.config/zsh", u->home);
	setenv("ZDOTDIR", zdotdir, 1);
	/* set critical paths so zshrc can find them */
	char zshcfg[300], zsh[300], xdg_config[300], xdg_data[300];
	snprintf(zshcfg,     sizeof(zshcfg),     "%s/.config/zsh/zshcfg",     u->home);
	snprintf(zsh,        sizeof(zsh),        "%s/.config/zsh/zshcfg/OMZ", u->home);
	snprintf(xdg_config, sizeof(xdg_config), "%s/.config",                u->home);
	snprintf(xdg_data,   sizeof(xdg_data),   "%s/.local/share",           u->home);
	setenv("ZSHCFG",         zshcfg,     1);
	setenv("ZSH",            zsh,        1);
	setenv("XDG_CONFIG_HOME",xdg_config, 1);
	setenv("XDG_DATA_HOME",  xdg_data,   1);
	/* set PATH to include user scripts */
	char path[1024];
	snprintf(path, sizeof(path),
		"%s/.local/bin:"
		"%s/.local/bin/mrblocks-scripts:"
		"%s/.local/bin/mrpanel-genmon-scripts:"
		"%s/.local/bin/system-scripts:"
		"/usr/local/bin:/usr/bin:/bin",
		u->home, u->home, u->home, u->home);
	setenv("PATH", path, 1);
	chdir(u->home);
	char xinitrc[300];
	snprintf(xinitrc, sizeof(xinitrc), "%s/.xinitrc", u->home);
	if (access(xinitrc, X_OK) == 0) {
		char cmd[512];
		snprintf(cmd, sizeof(cmd), "exec dbus-run-session %s", xinitrc);
		execl("/bin/zsh", "zsh", "--login", "-c", cmd, NULL);
	} else {
		execl("/usr/bin/dbus-run-session", "dbus-run-session", "/usr/bin/dwm", NULL);
	}
}

int main(void) {
	char *display = getenv("DISPLAY");
	dpy = XOpenDisplay(display ? display : ":0");
	if (!dpy) { fprintf(stderr, "Cannot open display :0\n"); return 1; }
	screen = DefaultScreen(dpy);
	root   = RootWindow(dpy, screen);
	vis    = DefaultVisual(dpy, screen);
	cmap   = DefaultColormap(dpy, screen);

	get_primary_monitor();
	get_users();
	if (nusers == 0) { fprintf(stderr, "No users found\n"); return 1; }

	XSetWindowAttributes wa;
	wa.override_redirect = True;
	wa.background_pixel  = mkcolor(BG_COLOR);
	wa.event_mask        = KeyPressMask|ButtonPressMask|ExposureMask;
	win = XCreateWindow(dpy, root, 0, 0, sw, sh, 0,
		DefaultDepth(dpy, screen), InputOutput, vis,
		CWOverrideRedirect|CWBackPixel|CWEventMask, &wa);

	XMapRaised(dpy, win);
	XGrabKeyboard(dpy, win, True, GrabModeAsync, GrabModeAsync, CurrentTime);
	XGrabPointer(dpy, win, True, ButtonPressMask,
		GrabModeAsync, GrabModeAsync, win, None, CurrentTime);

	gc            = XCreateGC(dpy, win, 0, NULL);
	xdraw         = XftDrawCreate(dpy, win, vis, cmap);
	font_title    = XftFontOpenName(dpy, screen, FONT_TITLE);
	font_subtitle = XftFontOpenName(dpy, screen, FONT_SUBTITLE);
	font_input    = XftFontOpenName(dpy, screen, FONT_INPUT);
	font_label    = XftFontOpenName(dpy, screen, FONT_LABEL);
	font_clock    = XftFontOpenName(dpy, screen, FONT_CLOCK);
	font_date     = XftFontOpenName(dpy, screen, FONT_DATE);
	font_user     = XftFontOpenName(dpy, screen, FONT_USER);
	font_avatar   = XftFontOpenName(dpy, screen, FONT_AVATAR);
	font_fa       = XftFontOpenName(dpy, screen, FONT_FA);
	font_fa_lg    = XftFontOpenName(dpy, screen, FONT_FA_LG);

	redraw();

	XEvent ev;
	while (!auth_ok) {
		struct timeval tv = { 1, 0 };
		int fd = ConnectionNumber(dpy);
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		if (select(fd+1, &fds, NULL, NULL, &tv) == 0) { redraw(); continue; }

		XNextEvent(dpy, &ev);
		if (ev.type == Expose) {
			redraw();
		} else if (ev.type == ButtonPress) {
			int bx = ev.xbutton.x;
			int by = ev.xbutton.y;

			/* eye */
			if (bx >= eye_x && bx <= eye_x+eye_w &&
			    by >= eye_y && by <= eye_y+eye_h) {
				show_pass = !show_pass;
				redraw();
				continue;
			}

			/* user buttons */
			int cols = (nusers > 3) ? 3 : nusers;
			if (cols < 1) cols = 1;
			int gap = 12;
			int total_w = cols * USER_BTN_W + (cols-1) * gap;
			int card_x  = sw/2 - CARD_W/2;
			int card_y  = sh/2 - CARD_H/2;
			int start_x = card_x + CARD_W/2 - total_w/2;
			int uy      = card_y + 80;
			for (int i = 0; i < nusers; i++) {
				int col = i % cols;
				int row = i / cols;
				int ubx = start_x + col * (USER_BTN_W + gap);
				int uby = uy + row * (USER_BTN_H + gap);
				if (bx >= ubx && bx <= ubx+USER_BTN_W &&
				    by >= uby && by <= uby+USER_BTN_H) {
					sel_user = i;
					memset(pass_buf, 0, sizeof(pass_buf));
					pass_len = 0;
					strcpy(error_msg, "");
					fail_count = 0;
				}
			}

			/* login button */
			int ix   = card_x + 28;
			int iw   = CARD_W - 56;
			int py   = card_y + 218;
			int dots_y = py + INPUT_H;
			int lby  = dots_y + dots_height() + 4;
			if (bx >= ix && bx <= ix+iw &&
			    by >= lby && by <= lby+50)
				try_login();

			redraw();
		} else if (ev.type == KeyPress) {
			char buf[32] = {0};
			KeySym ks;
			XLookupString(&ev.xkey, buf, sizeof(buf), &ks, NULL);
			if (ks == XK_Return || ks == XK_KP_Enter) {
				try_login();
			} else if (ks == XK_Tab) {
				sel_user = (sel_user + 1) % nusers;
				memset(pass_buf, 0, sizeof(pass_buf));
				pass_len = 0;
				strcpy(error_msg, "");
				fail_count = 0;
			} else if (ks == XK_BackSpace) {
				if (pass_len > 0) pass_buf[--pass_len] = '\0';
			} else if (ks == XK_Escape) {
				memset(pass_buf, 0, sizeof(pass_buf));
				pass_len = 0;
				strcpy(error_msg, "");
			} else if (buf[0] >= 32 && buf[0] < 127) {
				if (pass_len < 255) pass_buf[pass_len++] = buf[0];
			}
			redraw();
		}
	}

	XUngrabKeyboard(dpy, CurrentTime);
	XUngrabPointer(dpy, CurrentTime);
	XDestroyWindow(dpy, win);
	XCloseDisplay(dpy);

	pid_t pid = fork();
	if (pid == 0) {
		start_session();
		exit(1);
	} else if (pid > 0) {
		int status;
		waitpid(pid, &status, 0);
	}
	return 0;
}
