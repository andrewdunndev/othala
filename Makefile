.PHONY: help brand

help:
	@echo "dunn.dev/othala — SSO substrate (Ory Kratos + Hydra + Astro UI); glauth-kratos LDAP bridge at gitlab.com/dunn.dev/kratos-ldap"
	@echo ""
	@echo "Status:"
	@echo "  See docs/STATUS.md for current direction."
	@echo ""
	@echo "Brand:"
	@echo "  brand         regenerate avatar.png + brand.png from the SVGs"

# Regenerate the derived brand artifacts after editing hero.svg / avatar.svg.
# favicon.svg is hand-authored and not part of brand.png. Recipe matches the
# dunn-design skill (avatar over hero, paper-palette padding).
brand:
	rsvg-convert -w 256  -h 256 -o avatar.png avatar.svg
	rsvg-convert -w 1600 -h 573 -o /tmp/h.png hero.svg
	rsvg-convert -w 800  -h 800 -o /tmp/a.png avatar.svg
	magick /tmp/a.png -background '#f4f4f4' -gravity center \
	  -extent 1600x800 /tmp/a-pad.png
	magick /tmp/a-pad.png /tmp/h.png -append \
	  -bordercolor '#f4f4f4' -border 24 brand.png
	rm -f /tmp/h.png /tmp/a.png /tmp/a-pad.png
