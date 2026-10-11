Baboon output generated with the exact key/ImageID indices used by run_metrics.
Original = S.load_image(1); UserKey=pool_key(5001); ImageID=pool_image_id(5001).
marked = protect_image(original, UserKey, ImageID).marked_image.
Step2 is the carrier immediately before tag embedding.
Compare original-to-marked for image fidelity; compare Step2-to-marked for tag-marking distortion.
